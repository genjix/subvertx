#include <bitcoin/address.hpp>
#include <bitcoin/constants.hpp>
#include <bitcoin/dialect.hpp>
#include <bitcoin/messages.hpp>
#include <bitcoin/kernel.hpp>
#include <bitcoin/types.hpp>
#include <bitcoin/transaction.hpp>
#include <bitcoin/network/network.hpp>
#include <bitcoin/util/assert.hpp>
#include <bitcoin/util/elliptic_curve_key.hpp>
#include <bitcoin/util/logger.hpp>
#include <bitcoin/util/ripemd.hpp>

#include <getopt.h>
#include <functional>
#include <iostream>
#include <string>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

using namespace libbitcoin;
using namespace libbitcoin::message;
using std::placeholders::_1;
using std::placeholders::_2;

const option long_opts[] = {
    {"previous-output", required_argument, NULL, 'p'},
    {"recipient", required_argument, NULL, 'r'},
    {"host", required_argument, NULL, 'H'},
    {"port", required_argument, NULL, 'P'},
    {"help", required_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0}
};

const char* opt_string = "p:r:H:P:h";

void display_help()
{
    puts("Usage: mktx COMMAND [ARGS]...");
    puts("");
    puts("Commands:");
    puts("");
    puts("  create\tCreate a new transaction and output the binary data");
    puts("  send\t\tSend a transaction to the network, reading from STDIN");
    puts("");
    puts("Options:");
    puts("");
    puts(" -p, --previous-output\tPrevious output in the form OUT:INDEX");
    puts(" -r, --recipient\tSpecify a destination ADDRESS:AMOUNT");
    puts("\t\t\tAMOUNT uses internal bitcoin values");
    puts("\t\t\t  0.1 BTC = 0.1 * 10^8 = 1000000");
    puts(" -H, --host\t\tHost of bitcoin node");
    puts(" -P, --port\t\tPort for bitcoin node");
    puts(" -h, --help\t\tThis help text");
    puts("");
    puts("Please email suggestions and questions to <genjix@riseup.net>.");
}

void error_exit(const std::string& message, int status=1)
{
    log_error() << "mktx: " << message;
    exit(status);
}

std::mutex mutex;
std::condition_variable condition;
bool finished = false;

void close_application()
{
    std::unique_lock<std::mutex> lock(mutex);
    finished = true;
    condition.notify_one();
}

void handle_tx_sent(const std::error_code& ec)
{
    if (ec)
        error_exit(ec.message());
    close_application();
}

void handle_connected(const std::error_code& ec, channel_handle chandle,
    network_ptr net, const message::transaction& tx)
{
    if (ec)
        error_exit(ec.message());
    log_info() << "Connected";
    net->send(chandle, tx, handle_tx_sent);
}

script build_output_script(const short_hash& public_key_hash)
{
    script result;
    result.push_operation({opcode::dup, data_chunk()});
    result.push_operation({opcode::hash160, data_chunk()});
    result.push_operation({opcode::special,
        data_chunk(public_key_hash.begin(), public_key_hash.end())});
    result.push_operation({opcode::equalverify, data_chunk()});
    result.push_operation({opcode::checksig, data_chunk()});
    return result;
}

struct destination
{
    std::string address;
    uint64_t amount;
};

void create(std::vector<output_point> previous_outputs,
    std::vector<destination> endpoints, const elliptic_curve_key& key)
{
    if (previous_outputs.size() != 1)
        error_exit("more than 1 previous output not supported yet");

    transaction tx;
    tx.version = 1;
    tx.locktime = 0;

    transaction_input input;
    input.previous_output = previous_outputs[0];
    input.sequence = 4294967295;
    data_chunk public_key = key.get_public_key();
    input.input_script.push_operation({opcode::special, public_key});
    tx.inputs.push_back(input);

    for (const destination& dest: endpoints)
    {
        transaction_output output;
        output.value = dest.amount;
        short_hash dest_pubkey_hash = address_to_short_hash(dest.address);
        output.output_script = build_output_script(dest_pubkey_hash);
        tx.outputs.push_back(output);
    }

    // Rebuild previous output script
    script script_code = 
        build_output_script(generate_ripemd_hash(public_key));

    hash_digest tx_hash =
        script::generate_signature_hash(tx, 0, script_code, 1);
    if (tx_hash == null_hash)
        error_exit("error generating signature hash");
    data_chunk signature = key.sign(tx_hash);
    signature.push_back(0x01);

    script& input_script = tx.inputs[0].input_script;
    input_script = script();
    input_script.push_operation({opcode::special, signature});
    input_script.push_operation({opcode::special, public_key});

    original_dialect convert_tx;
    data_chunk raw_tx = convert_tx.to_network(tx);
    BITCOIN_ASSERT(raw_tx ==
        convert_tx.to_network(convert_tx.transaction_from_network(raw_tx)));
    log_info() << std::string(raw_tx.begin(), raw_tx.end());
}

int send(const message::transaction& tx, 
    const std::string& hostname, unsigned short port)
{
    network_ptr net(new network_impl);
    handshake_connect(net, hostname, port, 
        std::bind(&handle_connected, _1, _2, net, tx));

    std::unique_lock<std::mutex> lock(mutex);
    condition.wait(lock, []{ return finished; });
    // Display hash of sent transaction
    log_info() << pretty_hex(hash_transaction(tx));
    sleep(1);
    return 0;
}

std::string read_stdin()
{
    std::istreambuf_iterator<char> it(std::cin);
    std::istreambuf_iterator<char> end;
    return std::string(it, end);
}

private_data read_private_key()
{
    std::string raw_private_key = read_stdin();
    return private_data(raw_private_key.begin(), raw_private_key.end());
}

message::transaction read_transaction()
{
    std::string raw_tx_string = read_stdin();
    data_chunk raw_tx(raw_tx_string.begin(), raw_tx_string.end());
    original_dialect convert_tx;
    return convert_tx.transaction_from_network(raw_tx);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        display_help();
        return 0;
    }
    std::string command = argv[1];    
    argc--;
    argv++;

    std::vector<output_point> previous_outputs;
    std::vector<destination> endpoints;

    std::string hostname = "localhost";
    unsigned short port = 8333;

    int long_index = 0;
    int opt = getopt_long(argc, argv, opt_string, long_opts, &long_index);
    while (opt != -1)
    {
        switch (opt)
        {
            case 'p':
            {
                std::vector<std::string> output_parts;
                boost::split(output_parts, optarg, boost::is_any_of(":"));
                if (output_parts.size() != 2)
                    error_exit("output requires transaction hash and index");
                output_point prevout;
                prevout.hash = hash_from_pretty(output_parts[0]);
                if (prevout.hash == null_hash)
                    error_exit("malformed previous output transaction hash");
                prevout.index = boost::lexical_cast<uint32_t>(output_parts[1]);
                previous_outputs.push_back(prevout);
                break;
            }
            
            case 'r':
            {
                std::vector<std::string> dest_parts;
                boost::split(dest_parts, optarg, boost::is_any_of(":"));
                if (dest_parts.size() != 2)
                    error_exit("recipient requires address and amount");
                destination dest;
                dest.address = dest_parts[0];
                dest.amount = boost::lexical_cast<uint64_t>(dest_parts[1]);
                endpoints.push_back(dest);
                break;
            }

            case 'H':
                hostname = optarg;
                break;

            case 'P':
                port = boost::lexical_cast<unsigned short>(optarg);
                break;

            case 'h':
                display_help();
                return 0;

            case 0:
            default:
                return -1;
        }
        opt = getopt_long(argc, argv, opt_string, long_opts, &long_index);
    }

    size_t number_args = argc - 2, arg_index = 2;
    if (command == "create")
    {
        if (previous_outputs.empty())
            error_exit("need at least one previous output");
        if (endpoints.empty())
            error_exit("need at least one recipient");
        elliptic_curve_key key;
        if (!key.set_private_key(read_private_key()))
            error_exit("bad private key");
        create(previous_outputs, endpoints, key);
    }
    else if (command == "send")
    {
        message::transaction tx;
        try
        {
            tx = read_transaction();
        }
        catch (end_of_stream)
        {
            error_exit("bad transaction");
        }
        return send(tx, hostname, port);
    }
    else if (command == "help")
    {
        display_help();
        return 0;
    }
    else
        error_exit("not a valid command. See mktx help text.");
    // Should never happen!
    return 1;
}


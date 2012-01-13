#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>

#include <bitcoin/bitcoin.hpp>
#include <bitcoin/blockchain/bdb_blockchain.hpp>

using libbitcoin::blockchain_ptr;
//using libbitcoin::postgresql_blockchain;
using libbitcoin::bdb_blockchain;
using libbitcoin::data_chunk;
using libbitcoin::address_to_short_hash;
using libbitcoin::short_hash;
using libbitcoin::null_short_hash;

void display_help()
{
    puts("Usage: balance [BACKEND] [ADDRESS]");
    puts("");
    puts("BACKEND consists of a colon separated list of parameters.");
    puts("  Currently just: bdb");
}

void error_exit(const std::string& message, int status=1)
{
    std::cerr << "balance: " << message << std::endl;
    exit(status);
}

std::mutex mutex;
std::condition_variable condition;
bool finished = false;

void recv_balance(const std::error_code& ec, uint64_t value)
{
    if (ec)
        error_exit(ec.message());
    uint64_t significand = value / 100000000;
    std::cout << significand << "." << (value - significand) << std::endl;

    std::unique_lock<std::mutex> lock(mutex);
    finished = true;
    condition.notify_one();
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        display_help();
        return 0;
    }
    std::vector<std::string> backend_parameters;
    boost::split(backend_parameters, argv[1], boost::is_any_of(":"));
    BITCOIN_ASSERT(!backend_parameters.empty());
    blockchain_ptr backend;
    if (backend_parameters[0] == "postgresql")
    {
        /*if (backend_parameters.size() != 4)
            error_exit("PostgreSQL database backend requires 3 parameters");
        backend.reset(new postgresql_blockchain(core, backend_parameters[1],
            backend_parameters[2], backend_parameters[3]));*/
	error_exit("PostgreSQL backend is not available at this time.");
    }
    else if (backend_parameters[0] == "bdb")
    {
        backend = std::make_shared<bdb_blockchain>("database/");
    }
    else
        error_exit("invalid backend specified");

    short_hash pubkey_hash = address_to_short_hash(argv[2]);
    if (pubkey_hash == null_short_hash)
        error_exit("invalid bitcoin address supplied");
    backend->fetch_balance(pubkey_hash, recv_balance);

    std::unique_lock<std::mutex> lock(mutex);
    condition.wait(lock, []{ return finished; });
    return 0;
}


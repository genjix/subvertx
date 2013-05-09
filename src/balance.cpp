#include <condition_variable>
#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>

#include <bitcoin/bitcoin.hpp>
using namespace bc;

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

void blockchain_started(const std::error_code& ec)
{
    if (ec)
        log_fatal() << "error: " << ec.message();
    else
        log_info() << "Blockchain initialized!";
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
    async_service service(1);
    blockchain* backend = nullptr;
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
        bdb_blockchain* bdb_backend = new bdb_blockchain(service);
        bdb_backend->start("database", blockchain_started);
        backend = bdb_backend;
    }
    else
        error_exit("invalid backend specified");

    payment_address address;
    if (!address.set_encoded(argv[2]))
        error_exit("invalid bitcoin address_type supplied");
    error_exit("program disabled! need to fix it someitme :)");
    //backend->fetch_balance(address.hash(), recv_balance);

    std::unique_lock<std::mutex> lock(mutex);
    condition.wait(lock, []{ return finished; });
    delete backend;
    return 0;
}


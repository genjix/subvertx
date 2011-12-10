#include <iostream>

#include <bitcoin/types.hpp>
#include <bitcoin/kernel.hpp>
#include <bitcoin/blockchain/postgresql_blockchain.hpp>
#include <bitcoin/util/logger.hpp>

using namespace libbitcoin;

void display_balance(const std::error_code& ec, uint64_t value)
{
    if (ec)
    {
        log_fatal() << ec.message();
        return;
    }
    log_info() << "Balance: " << value;
}

int main()
{
    kernel_ptr app(new kernel());
    blockchain_ptr app_blockchain(new postgresql_blockchain(
        app, "bitcoin", "genjix", ""));
    app->register_blockchain(app_blockchain);

    data_chunk address = 
        bytes_from_pretty("12 ab 8d c5 88 ca 9d 57 87 dd "
                          "e7 eb 29 56 9d a6 3c 3a 23 8c");
    app_blockchain->fetch_balance(address, display_balance);

    std::cin.get();
    return 0;
}


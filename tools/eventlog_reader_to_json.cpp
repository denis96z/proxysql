#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include "json.hpp" // Requires nlohmann/json.hpp

using json = nlohmann::json;

// Decodes a MySQL length-encoded integer from the stream.
// Returns true if decoding was successful.
bool decodeInt(std::istream &in, uint64_t &val) {
    unsigned char first;
    if (!in.read(reinterpret_cast<char*>(&first), 1))
        return false;
    if (first < 251) {
        val = first;
        return true;
    } else if (first == 0xfc) {
        uint16_t tmp;
        if (!in.read(reinterpret_cast<char*>(&tmp), sizeof(tmp)))
            return false;
        val = tmp;
        return true;
    } else if (first == 0xfd) {
        uint32_t tmp = 0;
        char buf[3] = {0};
        if (!in.read(buf, 3))
            return false;
        tmp = (unsigned char)buf[0] | 
              ((unsigned char)buf[1] << 8) | 
              ((unsigned char)buf[2] << 16);
        val = tmp;
        return true;
    } else if (first == 0xfe) {
        uint64_t tmp;
        if (!in.read(reinterpret_cast<char*>(&tmp), sizeof(tmp)))
            return false;
        val = tmp;
        return true;
    }
    return false;
}

// Reads a fixed-size value from the stream.
template <typename T>
bool readValue(std::istream &in, T &value) {
    in.read(reinterpret_cast<char*>(&value), sizeof(T));
    return in.good();
}

// Reads raw bytes into a string.
std::string readString(std::istream &in, uint64_t length) {
    std::vector<char> buf(length);
    if (!in.read(buf.data(), length))
        return "";
    return std::string(buf.begin(), buf.end());
}

json parseEvent(std::istream &in) {
    json j;
    // Read total_bytes (first 8 bytes)
    uint64_t total_bytes = 0;
    if (!readValue(in, total_bytes))
        throw std::runtime_error("Cannot read total_bytes");
    // j["total_bytes"] = total_bytes; // optional

    // Read event type (1 byte)
    unsigned char et;
    if (!readValue(in, et))
        throw std::runtime_error("Cannot read event type");
    j["event_type"] = et;

    // Read thread_id
    uint64_t thread_id = 0;
    if (!decodeInt(in, thread_id))
        throw std::runtime_error("Error decoding thread_id");
    j["thread_id"] = thread_id;

    // Username: first read its length then the raw string.
    uint64_t username_len = 0;
    if (!decodeInt(in, username_len))
        throw std::runtime_error("Error decoding username length");
    std::string username = readString(in, username_len);
    j["username"] = username;

    // Schemaname
    uint64_t schemaname_len = 0;
    if (!decodeInt(in, schemaname_len))
        throw std::runtime_error("Error decoding schemaname length");
    std::string schemaname = readString(in, schemaname_len);
    j["schemaname"] = schemaname;

    // Client string
    uint64_t client_len = 0;
    if (!decodeInt(in, client_len))
        throw std::runtime_error("Error decoding client length");
    std::string client = readString(in, client_len);
    j["client"] = client;

    // Host id (hid)
    uint64_t hid = 0;
    if (!decodeInt(in, hid))
        throw std::runtime_error("Error decoding hid");
    j["hid"] = hid;

    // If hid != UINT64_MAX then read server string.
    if (hid != UINT64_MAX) {
        uint64_t server_len = 0;
        if (!decodeInt(in, server_len))
            throw std::runtime_error("Error decoding server length");
        std::string server = readString(in, server_len);
        j["server"] = server;
    }

    // Start time and End time
    uint64_t start_time = 0, end_time = 0;
    if (!decodeInt(in, start_time))
        throw std::runtime_error("Error decoding start_time");
    if (!decodeInt(in, end_time))
        throw std::runtime_error("Error decoding end_time");
    j["start_time"] = start_time;
    j["end_time"] = end_time;

    // Client statement id (only for COM_STMT_PREPARE/EXECUTE events)
    uint64_t client_stmt_id = 0;
    if (et == /*COM_STMT_PREPARE=*/ 0 || et == /*COM_STMT_EXECUTE=*/ 1) { // adjust as needed
        if (!decodeInt(in, client_stmt_id))
            throw std::runtime_error("Error decoding client_stmt_id");
        j["client_stmt_id"] = client_stmt_id;
    }

    // affected_rows, last_insert_id, rows_sent, query_digest
    uint64_t affected_rows, last_insert_id, rows_sent, query_digest;
    if (!decodeInt(in, affected_rows))
        throw std::runtime_error("Error decoding affected_rows");
    if (!decodeInt(in, last_insert_id))
        throw std::runtime_error("Error decoding last_insert_id");
    if (!decodeInt(in, rows_sent))
        throw std::runtime_error("Error decoding rows_sent");
    if (!decodeInt(in, query_digest))
        throw std::runtime_error("Error decoding query_digest");
    j["affected_rows"] = affected_rows;
    j["last_insert_id"] = last_insert_id;
    j["rows_sent"] = rows_sent;
    j["query_digest"] = query_digest;

    // Query: first read its length then raw query bytes.
    uint64_t query_len = 0;
    if (!decodeInt(in, query_len))
        throw std::runtime_error("Error decoding query length");
    std::string query = readString(in, query_len);
    j["query"] = query;

    // If the event is COM_STMT_EXECUTE then read parameter block.
    if (et == /*COM_STMT_EXECUTE=*/ 1) { // adjust event code as needed
        // Read parameters count
        uint64_t num_params;
        if (!decodeInt(in, num_params))
            throw std::runtime_error("Error decoding parameter count");

        json jparams = json::array();
        // Calculate null bitmap size
        size_t bitmap_size = (num_params + 7) / 8;
        std::vector<unsigned char> null_bitmap(bitmap_size);
        if (!in.read(reinterpret_cast<char*>(null_bitmap.data()), bitmap_size))
            throw std::runtime_error("Error reading null bitmap");

        for (uint16_t i = 0; i < num_params; i++) {
            json jparam;
            // Read parameter type (2 bytes)
            uint16_t param_type;
            if (!readValue(in, param_type))
                throw std::runtime_error("Error reading parameter type");
            jparam["type"] = param_type;
            // Check if parameter is NULL using null bitmap.
            bool isNull = false;
            if (i < num_params) {
                isNull = (null_bitmap[i / 8] & (1 << (i % 8))) != 0;
            }
            if (isNull) {
                jparam["value"] = nullptr;
            } else {
                // Read encoded length of parameter value
                uint64_t param_value_len;
                if (!decodeInt(in, param_value_len))
                    throw std::runtime_error("Error decoding param value length");
                // Read raw parameter value bytes.
                std::string param_value = readString(in, param_value_len);
                jparam["value"] = param_value;
            }
            jparams.push_back(jparam);
        }
        j["parameters"] = jparams;
    }
    return j;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: bin2json <binary_log_file>" << std::endl;
        return 1;
    }
    std::ifstream infile(argv[1], std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Failed to open file: " << argv[1] << std::endl;
        return 1;
    }

    try {
        // In this example we assume one event record per file.
        json j = parseEvent(infile);
        // Output the JSON
        std::cout << j.dump(4) << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "Error parsing log file: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
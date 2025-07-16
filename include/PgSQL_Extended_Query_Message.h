#ifndef CLASS_PGSQL_EXTENDED_QUERY_MESSAGE_H
#define CLASS_PGSQL_EXTENDED_QUERY_MESSAGE_H

#include "proxysql.h"
#include "cpp.h"


/**
 * @brief Base class for handling PostgreSQL extended query messages.
 *
 * @tparam DATA    The structure type holding parsed message data.
 * @tparam DERIVED The derived message class type.
 */
template<typename DATA, typename DERIVED>
class Base_Extended_Query_Message {

public:
	Base_Extended_Query_Message() noexcept = default;
	~Base_Extended_Query_Message() noexcept;

	// Disable copy and move operations to prevent slicing and ensure proper ownership semantics
	Base_Extended_Query_Message(const Base_Extended_Query_Message&) = delete;
	Base_Extended_Query_Message& operator=(const Base_Extended_Query_Message&) = delete;
	Base_Extended_Query_Message(Base_Extended_Query_Message&&) = delete;
	Base_Extended_Query_Message& operator=(Base_Extended_Query_Message&&) = delete;

	/**
	  * @brief Releases the ownership of the packet and returns a new message object.
	  *
	  * This method transfers ownership of the packet data to a new message object
	  * and resets the current message's internal state.
	  *
	  * @return A pointer to the newly created message object with transferred data.
	  */
	DERIVED* release() noexcept;

	/**
	  * @brief Detaches the packet data from the message.
	  *
	  * @return The detached packet data as a PtrSize_t structure.
	  */
	PtrSize_t detach() noexcept;

	/**
	 * @brief Returns a const reference to the parsed data.
	 *
	 * @return Const reference to the DATA structure.
	 */
	inline const DATA& data() const noexcept {
		return _data;
	}

protected:
	/**
	 * @brief Provides mutable access to the internal data.
	 *
	 * @return Reference to the DATA structure.
	 */
	inline DATA& mutable_data() noexcept {
		return _data;
	}

	/**
	 * @brief Moves ownership of packet data from source to internal storage.
	 *
	 * @param src Rvalue reference to the source PtrSize_t.
	 */
	inline void move_pkt(PtrSize_t&& src) noexcept {
		_pkt = { src.size, src.ptr };
		src = PtrSize_t{ 0, nullptr };
	}

private:
	DATA _data = {};		///< Parsed message data.
	PtrSize_t _pkt = {};	///< Packet data pointer.
};

struct PgSQL_Parse_Data {
	const char* stmt_name;		// The name of the prepared statement
	const char* query_string;	// The query string to be prepared
	uint16_t num_param_types;		// Number of parameter types specified
	const uint32_t* param_types;	// Array of parameter types (can be nullptr if none)
};

class PgSQL_Parse_Message : public Base_Extended_Query_Message<PgSQL_Parse_Data,PgSQL_Parse_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Parse_Message from the provided packet.
	 *
	 * This method extracts the statement name, query string, parameter types,
	 * and initializes the internal state of the PgSQL_Parse_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Parse_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

struct PgSQL_Describe_Data {
	const char* stmt_name;		// The name of the prepared statement or portal
	uint8_t stmt_type;			// 'S' for statement, 'P' for portal
};

class PgSQL_Describe_Message : public Base_Extended_Query_Message<PgSQL_Describe_Data, PgSQL_Describe_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Describe_Message from the provided packet.
	 *
	 * This method extracts the statement type and name from the packet and
	 * initializes the internal state of the PgSQL_Describe_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Describe_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

struct PgSQL_Close_Data {
	uint8_t stmt_type;		// 'S' for statement, 'P' for portal
	const char* stmt_name;	// The name of the prepared statement or portal
};

// Class for handling Close messages for prepared statements and portals
class PgSQL_Close_Message : public Base_Extended_Query_Message<PgSQL_Close_Data,PgSQL_Close_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Close_Message from the provided packet.
	 *
	 * This method extracts the statement type and name from the packet and
	 * initializes the internal state of the PgSQL_Close_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Close_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

struct PgSQL_Bind_Data {
	const char* portal_name;		// The name of the portal to bind
	const char* stmt_name;			// The name of the prepared statement to bind
	uint16_t num_param_formats;		// Number of parameter formats
	uint16_t num_param_values;		// Number of parameter values
	uint16_t num_result_formats;	// Number of result format codes

private:
	const unsigned char* param_formats_start_ptr; // Pointer to the start of parameter formats (can be nullptr if none)
	const unsigned char* param_values_start_ptr; // Pointer to the start of parameter values (can be nullptr if none)
	const unsigned char* result_formats_start_ptr; // Pointer to the start of result formats (can be nullptr if none)

	friend class PgSQL_Bind_Message;
};

class PgSQL_Bind_Message : public Base_Extended_Query_Message<PgSQL_Bind_Data,PgSQL_Bind_Message> {
public:
	typedef struct {
		int32_t len;         // Length of value (-1 for NULL)
		const unsigned char* value;  // Pointer to value data
	} ParamValue_t;

	// Iterator context for parameter values
	typedef struct {
		const unsigned char* current;   // Current position in values
		uint16_t remaining;            // Parameters remaining
	} IteratorCtx;

	/**
	 * @brief Parses the PgSQL_Bind_Message from the provided packet.
	 *
	 * This method extracts the portal name, statement name, parameter formats,
	 * parameter values, and result formats from the packet and initializes the
	 * internal state of the PgSQL_Bind_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Bind_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);

	// Initialize param format iterator
	void init_param_format_iter(IteratorCtx* ctx) const;
	// Initialize parameter value iterator
	void init_param_value_iter(IteratorCtx* ctx) const;
	// Get next parameter value
	bool next_param_value(IteratorCtx* ctx, ParamValue_t* out) const;
	// Initialize result format iterator
	void init_result_format_iter(IteratorCtx* ctx) const;
	// Get next format value
	bool next_format(IteratorCtx* ctx, uint16_t* out) const;
};

struct PgSQL_Execute_Data {
	const char* portal_name;	// The name of the portal to execute
	uint32_t max_rows;			// Maximum number of rows to return (0 for no limit)
};

class PgSQL_Execute_Message : public Base_Extended_Query_Message<PgSQL_Execute_Data,PgSQL_Execute_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Execute_Message from the provided packet.
	 *
	 * This method extracts the portal name and maximum rows from the packet
	 * and initializes the internal state of the PgSQL_Execute_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Execute_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

#endif /* CLASS_PGSQL_EXTENDED_QUERY_MESSAGE_H */

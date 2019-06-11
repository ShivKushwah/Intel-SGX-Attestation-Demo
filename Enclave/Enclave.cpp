#include "Enclave_t.h"
#include "sgx_eid.h"
#include "sgx_dh.h"

//error_codes.h
typedef uint32_t ATTESTATION_STATUS;

#define SUCCESS                          0x00
#define INVALID_PARAMETER                0xE1
#define VALID_SESSION                    0xE2
#define INVALID_SESSION                  0xE3
#define ATTESTATION_ERROR                0xE4
#define ATTESTATION_SE_ERROR             0xE5
#define IPP_ERROR                        0xE6
#define NO_AVAILABLE_SESSION_ERROR       0xE7
#define MALLOC_ERROR                     0xE8
#define ERROR_TAG_MISMATCH               0xE9
#define OUT_BUFFER_LENGTH_ERROR          0xEA
#define INVALID_REQUEST_TYPE_ERROR       0xEB
#define INVALID_PARAMETER_ERROR          0xEC
#define ENCLAVE_TRUST_ERROR              0xED
#define ENCRYPT_DECRYPT_ERROR            0xEE
#define DUPLICATE_SESSION                0xEF

//dh_session_protocol.h
#include "sgx_ecp_types.h"
#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_attributes.h"

#define NONCE_SIZE         16
#define MAC_SIZE           16

#define MSG_BUF_LEN        sizeof(ec_pub_t)*2
#define MSG_HASH_SZ        32


//Session information structure
typedef struct _la_dh_session_t
{
    uint32_t  session_id; //Identifies the current session
    uint32_t  status; //Indicates session is in progress, active or closed
    union
    {
        struct
        {
			sgx_dh_session_t dh_session;
        }in_progress;

        struct
        {
            sgx_key_128bit_t AEK; //Session Key
            uint32_t counter; //Used to store Message Sequence Number
        }active;
    };
} dh_session_t;


int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}

//Makes use of the sample code function to establish a secure channel with the destination enclave (Test Vector)
uint32_t test_create_session(sgx_enclave_id_t src_enclave_id,
                         sgx_enclave_id_t dest_enclave_id)
{
    
    ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;
    
    //Core reference code function for creating a session
    //ke_status = create_session(src_enclave_id, dest_enclave_id, &dest_session_info);
    /* 
    //Insert the session information into the map under the corresponding destination enclave id
    if(ke_status == SUCCESS)
    {
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
    */
   return 0;
}

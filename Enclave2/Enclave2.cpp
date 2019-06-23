#include "Enclave2_t.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_dh.h"

//other
#include <stdio.h>
#include <string.h>
#include <map>

//datatypes.h
typedef struct _session_id_tracker_t
{
    uint32_t          session_id;
}session_id_tracker_t;

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

//datatypes.h
//datatypes.h
#include "sgx_tseal.h"

#define DH_KEY_SIZE        20
#define NONCE_SIZE         16
#define MAC_SIZE           16
#define MAC_KEY_SIZE       16
#define PADDING_SIZE       16

#define TAG_SIZE        16
#define IV_SIZE            12

#define DERIVE_MAC_KEY      0x0
#define DERIVE_SESSION_KEY  0x1
#define DERIVE_VK1_KEY      0x3
#define DERIVE_VK2_KEY      0x4

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define MESSAGE_EXCHANGE 0x0
#define ENCLAVE_TO_ENCLAVE_CALL 0x1

#define INVALID_ARGUMENT                   -2   ///< Invalid function argument
#define LOGIC_ERROR                        -3   ///< Functional logic error
#define FILE_NOT_FOUND                     -4   ///< File not found

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

#define MAX_SESSION_COUNT  16

session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];
//std::map<sgx_enclave_id_t, dh_session_t>g_dest_session_info_map;
sgx_enclave_id_t g_dest_session_info_map_id;
dh_session_t g_dest_session_info_map_session;
uint32_t g_session_count = 0;



int generate_random_number2() {
    ocall_print("Processing random number generation...");
    return 41;
}

//Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if(!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //if the session structure is untintialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (g_session_id_tracker[i] == NULL)
        {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;

}

//Handle the request from Source Enclave for a session
ATTESTATION_STATUS session_request(sgx_enclave_id_t src_enclave_id,
                          sgx_dh_msg1_t *dh_msg1,
                          uint32_t *session_id )
{
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if(!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    } 
    
    //get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS)
        return status; //no more sessions available

    //Allocate memory for the session id tracker
    g_session_id_tracker[*session_id] = (session_id_tracker_t *)malloc(sizeof(session_id_tracker_t));
    if(!g_session_id_tracker[*session_id])
    {
        return MALLOC_ERROR;
    }


    memset(g_session_id_tracker[*session_id], 0, sizeof(session_id_tracker_t));
    g_session_id_tracker[*session_id]->session_id = *session_id;
    session_info.status = IN_PROGRESS;


    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        free(g_session_id_tracker[*session_id]);
        return status;
    }
 
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    //Store the session information under the correspoding source enlave id key
    g_dest_session_info_map_id = src_enclave_id;
    g_dest_session_info_map_session = session_info;
    
    return status;
    
}


//Respond to the request from the Source Enclave to close the session
ATTESTATION_STATUS end_session(sgx_enclave_id_t src_enclave_id)
{
    ATTESTATION_STATUS status = SUCCESS;
    int i;
    dh_session_t session_info;
    uint32_t session_id;
    /*
    //Get the session information from the map corresponding to the source enclave id
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_dest_session_info_map.find(src_enclave_id);
    if(it != g_dest_session_info_map.end())
    {
        session_info = it->second;
    }
    else
    {
        return INVALID_SESSION;
    }
    */
   session_info = g_dest_session_info_map_session;

    session_id = session_info.session_id;
    //Erase the session information for the current session
    //g_dest_session_info_map_session = NULL;
    //TODO uncomment above and make it a g_dest a pointer and have it point to null


    //Update the session id tracker
    if (g_session_count > 0)
    {
        //check if session exists
        for (i=1; i <= MAX_SESSION_COUNT; i++)
        {
            if(g_session_id_tracker[i-1] != NULL && g_session_id_tracker[i-1]->session_id == session_id)
            {
                memset(g_session_id_tracker[i-1], 0, sizeof(session_id_tracker_t));
                free(g_session_id_tracker[i-1]);
                g_session_count--;
                break;
            }
        }
    }

    return status;

}

//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
ATTESTATION_STATUS exchange_report(sgx_enclave_id_t src_enclave_id,
                          sgx_dh_msg2_t *dh_msg2,
                          sgx_dh_msg3_t *dh_msg3,
                          uint32_t session_id)
{
    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    if(!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));

     
    do
    {
        /* 
        //Retreive the session information for the corresponding source enclave id
        std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_dest_session_info_map.find(src_enclave_id);
        if(it != g_dest_session_info_map.end())
        {
            session_info = &it->second;
        }
        else
        {
            status = INVALID_SESSION;
            break;
        }
        */

       session_info = &g_dest_session_info_map_session;


        if(session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        dh_msg3->msg3_body.additional_prop_length = 0;
        //Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, 
                                                       dh_msg3, 
                                                       &sgx_dh_session, 
                                                       &dh_aek, 
                                                       &initiator_identity);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }
        
        //TODO figure out where this method is coming from
        //Verify source enclave's trust
        //   if(verify_peer_enclave_trust(&initiator_identity) != SUCCESS)
        // {
        //     return INVALID_SESSION;
        // }

        //save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
        g_session_count++;
    }while(0);


    if(status != SUCCESS)
    {
        end_session(src_enclave_id);
    }


    return status;

}




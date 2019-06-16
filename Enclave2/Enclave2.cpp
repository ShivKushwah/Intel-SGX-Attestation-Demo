#include "Enclave2_t.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_dh.h"

typedef uint32_t ATTESTATION_STATUS;


int generate_random_number2() {
    ocall_print("Processing random number generation...");
    return 41;
}

//Handle the request from Source Enclave for a session
ATTESTATION_STATUS session_request(sgx_enclave_id_t src_enclave_id,
                          sgx_dh_msg1_t *dh_msg1,
                          uint32_t *session_id )
{
    ocall_print("inside session_request");
    /* 
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
        SAFE_FREE(g_session_id_tracker[*session_id]);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    //Store the session information under the correspoding source enlave id key
    g_dest_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(src_enclave_id, session_info));
    
    return status;
    */
}

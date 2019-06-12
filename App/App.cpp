#include <stdio.h>
#include <iostream>
#include "sgx_dh.h"
#include "Enclave_u.h"
#include "Enclave2_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

//error_codes.h
typedef uint32_t ATTESTATION_STATUS;

#define VALID_SESSION                    0xE2
#define INVALID_SESSION                  0xE3

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global2_eid = 1;


// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

ATTESTATION_STATUS session_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
    printf("Got here!");
    /*
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;

	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}

	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave1_session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
			break;
		case 2:
			ret = Enclave2_session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
			break;
		case 3:
			ret = Enclave3_session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
			break;
	}
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else
    */	
	    return INVALID_SESSION;

}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    if (initialize_enclave(&global2_eid, "enclave2.token", "enclave2.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    sgx_status_t status;
    
    uint32_t ret_status;
    status = test_create_session(global_eid, &ret_status, global_eid, global2_eid);
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    
    int ptr;
    status = generate_random_number(global_eid, &ptr);
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr);

    int ptr2;
    sgx_status_t status2 = generate_random_number2(global2_eid, &ptr2);
    std::cout << status2 << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr2);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;

    return 0;
}



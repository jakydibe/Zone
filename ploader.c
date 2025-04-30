#include <windows.h>
#include <stdio.h>
#include <stdlib.h>


#define THREAD_EXECUTION_MODE 0

// void execute_payload(const unsigned char *payload, size_t payload_size) {
//     void *exec_mem;
//     DWORD old_protect;

//     // Allocate executable memory
//     exec_mem = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//     if (exec_mem == NULL) {
//         fprintf(stderr, "Failed to allocate memory\n");
//         return;
//     }

//     // Copy the payload to the allocated memory
//     memcpy(exec_mem, payload, payload_size);

//     // // Change the memory protection to executable
//     // if (!VirtualProtect(exec_mem, payload_size, PAGE_EXECUTE_READ, &old_protect)) {
//     //     fprintf(stderr, "Failed to set memory as executable\n");
//     //     VirtualFree(exec_mem, 0, MEM_RELEASE);
//     //     return;
//     // }

//     // Execute the payload

//     // ((void(*)())exec_mem)();

//     // create a thread

//     if (THREAD_EXECUTION_MODE){
//         HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
//         if (thread == NULL) {
//             fprintf(stderr, "Failed to create thread\n");
//             VirtualFree(exec_mem, 0, MEM_RELEASE);
//             return;
//         }
//         WaitForSingleObject(thread, INFINITE);
//     }
//     else{
//         ((void(*)())exec_mem)();
//         // Sleep(25000);
//     }
//     // Free the allocated memory
//     VirtualFree(exec_mem, 0, MEM_RELEASE);
// }

void execute_payload(unsigned char *payload, size_t payload_size) {
    void *exec_mem;
    DWORD old_protect;

    // Allocate executable memory
    exec_mem = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return;
    }

    // Copy the payload to the allocated memory
    memcpy(exec_mem, payload, payload_size);

    // Change the memory protection to executable
    if (!VirtualProtect(exec_mem, payload_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        fprintf(stderr, "Failed to set memory as executable\n");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    // Execute the payload
    ((void(*)())exec_mem)();

    // Free the allocated memory
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <payload_file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", argv[1]);
        return 1;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // print payload size
    printf("Payload size: %ld\n", file_size);

    // Allocate memory to read the payload
    unsigned char *payload = malloc(file_size);
    if (payload == NULL) {
        fprintf(stderr, "Failed to allocate memory for payload\n");
        fclose(file);
        return 1;
    }

    // Read the payload from the file
    if (fread(payload, 1, file_size, file) != file_size) {
        fprintf(stderr, "Failed to read payload from file\n");
        free(payload);
        fclose(file);
        return 1;
    }

    fclose(file);

    // Execute the payload
    execute_payload(payload, file_size);

    free(payload);
    return 0;
}

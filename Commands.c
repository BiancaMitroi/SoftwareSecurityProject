#include "Commands.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

HANDLE g_hThreadPool = NULL; // Global handle to thread pool

#include <wincrypt.h>

#define HASH_SIZE 32 // SHA-256 produces a 32-byte hash

BOOL HashPassword(const char* password, char* hashedPassword)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[HASH_SIZE];
    DWORD hashSize = HASH_SIZE;
    BOOL result = FALSE;

    // Use `password` to create a cryptographic hash
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        printf("Error acquiring cryptographic context for password '%s': %u\n", password, GetLastError());
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        printf("Error creating hash object for password '%s': %u\n", password, GetLastError());
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0))
    {
        printf("Error hashing password data '%s': %u\n", password, GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        for (DWORD i = 0; i < hashSize; i++)
        {
            sprintf(&hashedPassword[i * 2], "%02x", hash[i]);
        }
        result = TRUE;
    }
    else
    {
        printf("Error retrieving hash for password '%s': %u\n", password, GetLastError());
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return result;
}


NTSTATUS WINAPI SafeStorageInit(VOID)
{
    g_hThreadPool = CreateThreadpool(NULL);
    if (!g_hThreadPool)
    {
        printf("Error initializing global thread pool\n");
        return STATUS_UNSUCCESSFUL;
    }

    TP_POOL_STACK_INFORMATION poolInfo;
    poolInfo.StackCommit = 4;
    SetThreadpoolStackInformation(g_hThreadPool, &poolInfo);

    return STATUS_SUCCESS;
}


VOID WINAPI SafeStorageDeinit(VOID)
{
    if (g_hThreadPool)
    {
        CloseThreadpool(g_hThreadPool);
        g_hThreadPool = NULL;
    }
}


#define MAX_USERNAME 10
#define MAX_PASSWORD 256
#define USERS_FILE "users.txt"

// Helper function to check if directory exists
BOOL DirectoryExists(const char* dirPath)
{
    DWORD fileAttrib = GetFileAttributesA(dirPath);
    printf("Checking if directory exists at '%s'\n", dirPath);
    return (fileAttrib != INVALID_FILE_ATTRIBUTES && (fileAttrib & FILE_ATTRIBUTE_DIRECTORY));
}   

// Helper function to store hashed password
// StoreHashedPassword function updated with real hashing
NTSTATUS StoreHashedPassword(const char* username, const char* password)
{
    FILE* file = fopen(USERS_FILE, "a");
    if (!file)
    {
        printf("Error opening file '%s' for username '%s'\n", USERS_FILE, username);
        return STATUS_UNSUCCESSFUL;
    }

    char hashedPassword[HASH_SIZE * 2 + 1];
    if (!HashPassword(password, hashedPassword))
    {
        fclose(file);
        return STATUS_UNSUCCESSFUL;
    }

    fprintf(file, "%s %s\n", username, hashedPassword);
    fclose(file);

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI SafeStorageHandleRegister(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength)
{
    if (UsernameLength < 5 || UsernameLength > MAX_USERNAME)
    {
        printf("Invalid Username length: %d for Username '%s'\n", UsernameLength, Username);
        return STATUS_UNSUCCESSFUL;
    }

    if (PasswordLength < 5 || PasswordLength > MAX_PASSWORD)
    {
        printf("Invalid Password length: %d for Password '%s'\n", PasswordLength, Password);
        return STATUS_UNSUCCESSFUL;
    }

    char userDir[MAX_PATH];
    sprintf(userDir, "users\\%s", Username);

    if (DirectoryExists(userDir))
    {
        printf("User '%s' already exists!\n", Username);
        return STATUS_UNSUCCESSFUL;
    }

    if (!CreateDirectoryA(userDir, NULL))
    {
        printf("Failed to create user directory '%s'\n", userDir);
        return STATUS_UNSUCCESSFUL;
    }

    if (StoreHashedPassword(Username, Password) != STATUS_SUCCESS)
    {
        printf("Failed to store hashed password for Username '%s'\n", Username);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

char* g_loggedInUser = NULL; // Global variable for the currently logged-in user

NTSTATUS WINAPI SafeStorageHandleLogin(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength)
{

    if (g_loggedInUser != NULL)
    {
        printf("A user '%s' is already logged in. Logout before logging in a new user.\n", g_loggedInUser);
        return STATUS_UNSUCCESSFUL;
    }

    FILE* file = fopen(USERS_FILE, "r");
    if (!file)
    {
        printf("Could not open users file '%s'\n", USERS_FILE);
        return STATUS_UNSUCCESSFUL;
    }

    char storedUsername[MAX_USERNAME];
    char storedPassword[HASH_SIZE * 2 + 1];
    char hashedInputPassword[HASH_SIZE * 2 + 1];

    if (!HashPassword(Password, hashedInputPassword))
    {
        fclose(file);
        return STATUS_UNSUCCESSFUL;
    }

    while (fscanf(file, "%s %s", storedUsername, storedPassword) != EOF)
    {
        storedUsername[MAX_USERNAME - 1] = 0;
        storedPassword[HASH_SIZE * 2] = 0;

        if (strcmp(storedUsername, Username) == 0)
        {
            if (strcmp(storedPassword, hashedInputPassword) == 0)
            {
                g_loggedInUser = (char*)malloc(UsernameLength + 1);
                if (g_loggedInUser == NULL)
                {
                    fclose(file);
                    return STATUS_NO_MEMORY;
                }
                strncpy(g_loggedInUser, Username, UsernameLength);
                g_loggedInUser[UsernameLength] = '\0';

                fclose(file);
                printf("Login successful for user '%s'\n", Username);
                return STATUS_SUCCESS;
            }
            else
            {
                printf("Invalid password for user '%s'\n", Username);
                fclose(file);
                return STATUS_UNSUCCESSFUL;
            }
        }
    }

    printf("Username '%s' not found.\n", Username);
    fclose(file);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI SafeStorageHandleLogout(VOID)
{
    if (g_loggedInUser == NULL)
    {
        printf("No user is currently logged in to log out.\n");
        return STATUS_UNSUCCESSFUL;
    }

    printf("Logging out user '%s'\n", g_loggedInUser);
    free(g_loggedInUser);
    g_loggedInUser = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI SafeStorageHandleStore(const char* SubmissionName, uint16_t SubmissionNameLength, const char* SourceFilePath, uint16_t SourceFilePathLength)
{
    if (!g_hThreadPool)
    {
        printf("Thread pool not initialized for storing file '%s'\n", SubmissionName);
        return STATUS_UNSUCCESSFUL;
    }

    // Ensure a user is logged in
    if (g_loggedInUser == NULL)
    {
        printf("No user is currently logged in. Cannot store file '%s'.\n", SubmissionName);
        return STATUS_UNSUCCESSFUL;
    }

    // Define the base directory for the logged-in user
    const char* baseDirectory = "users\\";

    // Construct the full path: "users\<logged_in_user>\<SubmissionName>"
    char fullPath[255];
    snprintf(fullPath, sizeof(fullPath), "%s%s\\%s", baseDirectory, g_loggedInUser, SubmissionName);

    // Try opening the source file
    HANDLE hSource = CreateFileA(SourceFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSource == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open source file '%s' for submission '%s'. Error: %lu\n", SourceFilePath, SubmissionName, GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // Ensure the user's directory exists in the "users" folder
    char userDir[255];
    snprintf(userDir, sizeof(userDir), "%s%s", baseDirectory, g_loggedInUser);
    if (!DirectoryExists(userDir))
    {
        printf("User directory '%s' does not exist. Please register or check path permissions.\n", userDir);
        CloseHandle(hSource);
        return STATUS_UNSUCCESSFUL;
    }

    // Open the destination file for writing in the user's directory
    HANDLE hDest = CreateFileA(fullPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create destination file '%s' for submission '%s'. Error: %lu\n", fullPath, SubmissionName, GetLastError());
        CloseHandle(hSource);
        return STATUS_UNSUCCESSFUL;
    }

    // Process the file in chunks and write to the destination
    const DWORD chunkSize = 4096;
    char buffer[4096];
    DWORD bytesRead = 0, bytesWritten = 0;

    while (ReadFile(hSource, buffer, chunkSize, &bytesRead, NULL) && bytesRead > 0)
    {
        if (!WriteFile(hDest, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead)
        {
            printf("Error writing to destination file '%s' for submission '%s'. Error: %lu\n", fullPath, SubmissionName, GetLastError());
            CloseHandle(hSource);
            CloseHandle(hDest);
            return STATUS_UNSUCCESSFUL;
        }
        printf("Processed chunk of %d bytes for submission '%s'\n", bytesRead, SubmissionName);
    }

    // Clean up handles after successful file transfer
    CloseHandle(hSource);
    CloseHandle(hDest);

    printf("File '%s' stored successfully for user '%s'.\n", SubmissionName, g_loggedInUser);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI SafeStorageHandleRetrieve(const char* SubmissionName, uint16_t SubmissionNameLength, const char* DestinationFilePath, uint16_t DestinationFilePathLength)
{
    if (!g_hThreadPool)
    {
        printf("Thread pool not initialized for retrieving file '%s'\n", SubmissionName);
        return STATUS_UNSUCCESSFUL;
    }

    char userFilePath[MAX_PATH];
    sprintf(userFilePath, "users\\%s\\%s", g_loggedInUser ? g_loggedInUser : "<logged_in_user>", SubmissionName);

    HANDLE hSource = CreateFileA(userFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSource == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open submission '%s' for user '%s'\n", SubmissionName, g_loggedInUser);
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE hDest = CreateFileA(DestinationFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hSource);
        printf("Failed to create destination file '%s' for submission '%s'\n", DestinationFilePath, SubmissionName);
        return STATUS_UNSUCCESSFUL;
    }

    const DWORD chunkSize = 4096;
    char buffer[4096];
    DWORD bytesRead = 0, bytesWritten = 0;

    while (ReadFile(hSource, buffer, chunkSize, &bytesRead, NULL) && bytesRead > 0)
    {
        WriteFile(hDest, buffer, bytesRead, &bytesWritten, NULL);
    }

    CloseHandle(hSource);
    CloseHandle(hDest);
    printf("Retrieved submission '%s' to '%s' for user '%s'\n", SubmissionName, DestinationFilePath, g_loggedInUser);

    return STATUS_SUCCESS;
}

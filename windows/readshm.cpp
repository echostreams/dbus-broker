#include <SDKDDKVer.h>
#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	int		shmem_size = 64;  // 16byte
	HANDLE	shmem = INVALID_HANDLE_VALUE;
	HANDLE	mutex = INVALID_HANDLE_VALUE;

	mutex = ::CreateMutex(NULL, FALSE, "mutex_sample_name");

	shmem = ::CreateFileMapping(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		shmem_size,
		"DBusDaemonAddressInfo-S-1-5-21-4096676153-118612250-1341447571-1001"
	);

	char* buf = (char*)::MapViewOfFile(shmem, FILE_MAP_ALL_ACCESS, 0, 0, shmem_size);


	for (unsigned int c = 0; c < 60; ++c) {
		// mutex lock
		WaitForSingleObject(mutex, INFINITE);

		printf("read shared memory...c=%d\n", buf[0]);

		// mutex unlock
		::ReleaseMutex(mutex);

		::Sleep(1000);
	}

	// release
	::UnmapViewOfFile(buf);
	::CloseHandle(shmem);
	::ReleaseMutex(mutex);

	return 0;
}
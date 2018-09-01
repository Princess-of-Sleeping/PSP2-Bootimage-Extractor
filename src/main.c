#include <psp2kern/kernel/modulemgr.h>

#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <taihen.h>


typedef struct {	//Read SceKernelBootimage offset + 0xD0
	uint32_t	unk0[2];
	uint32_t	boot_image_version;
	uint32_t	count;
	uint32_t	skbi2_start_offset;
} SceKernelBootimage1_t;

typedef struct {
	char		*module_path;
	uint32_t	offset;
	uint32_t	size;
} SceKernelBootimage2_t;

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

int (* _ksceKernelMountBootfs)(const char *bootImagePath) = NULL;
int (* _ksceKernelUmountBootfs)(void) = NULL;
int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info) = NULL;



int LogInit(char *log_path){

	return ksceIoOpen(log_path, SCE_O_TRUNC | SCE_O_CREAT | SCE_O_WRONLY, 0666);
}

int PathToFileName(const char *src_path, char *file_name_output){

	int i;

	for(i=strlen(src_path);i>0;i--)if(src_path[i] == 0x2F || src_path[i] == 0x3A)break;

	strcpy(file_name_output, src_path+i+1);

	return 0;
}

void SaveFile(char *save_path, void *buf, int size){

	SceIoStat stat;

	if(ksceIoGetstat(save_path, &stat) >= 0){
		return;
	}

	int fd = ksceIoOpen(save_path, SCE_O_TRUNC | SCE_O_CREAT | SCE_O_WRONLY, 0666);
	ksceIoWrite(fd, buf, size);
	ksceIoClose(fd);
}


int boot_image_extractor(void){

	int ret = 0;
	int log_fd;

	uint32_t seg0_addr;

	char module_name[0x30];
	char buffer[0x100];
	char path[0x300];

	va_list arglist;

	SceIoStat stat;

	SceKernelModuleInfo info;
	info.size = sizeof(info);

	tai_module_info_t tai_info;
	tai_info.size = sizeof(tai_info);

	if ((ret = _ksceKernelMountBootfs("os0:kd/bootimage.skprx")) < 0) {
		return ret;
	}

	if((ret = taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelBootimage", &tai_info)) < 0){
		_ksceKernelUmountBootfs();
		return ret;
	}

	if((ret = _ksceKernelGetModuleInfo(KERNEL_PID, tai_info.modid, &info)) < 0){
		_ksceKernelUmountBootfs();
		return ret;
	}

	if(ksceIoGetstat("ur0:dump/bootimage.skprx/;) log.txt", &stat) >= 0){
		_ksceKernelUmountBootfs();
		return SCE_KERNEL_START_SUCCESS;
	}



	void LogWrite(char *str, ...){

		va_start(arglist, str);
		vsnprintf(buffer, sizeof(buffer), str, arglist);
		va_end(arglist);
		ksceIoWrite(log_fd, buffer, strlen(buffer));
	}


	log_fd = LogInit("ur0:dump/bootimage.skprx/;) log.txt");

	seg0_addr = (uint32_t)(info.segments[0].vaddr);

	SceKernelBootimage1_t *skbi1 = (void*)seg0_addr + 0xD0;

	LogWrite("boot_image_version : 0x%08X\n", skbi1->boot_image_version);
	LogWrite("count : %d\n", skbi1->count);
	//LogWrite("skbi2_start_offset : 0x%X\n", skbi1->skbi2_start_offset);
	LogWrite("\n");


	for(int i=0;i<skbi1->count;i++){

		SceKernelBootimage2_t *skbi2 = (void*)skbi1->skbi2_start_offset + (sizeof(SceKernelBootimage2_t) * i);

		PathToFileName(skbi2->module_path, module_name);

		sprintf(path, "ur0:dump/bootimage.skprx/%s.elf", module_name);

		LogWrite("%s\n", path);
		LogWrite("file offset : 0x%X\n", (skbi2->offset-seg0_addr));
		LogWrite("size : 0x%X\n", skbi2->size);

		SaveFile(path, (void*)(skbi2->offset), skbi2->size);
	}

	ksceIoClose(log_fd);

	_ksceKernelUmountBootfs();

	return 0;
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp) {

	ksceIoMkdir("ur0:dump/", 0666);
	ksceIoMkdir("ur0:dump/bootimage.skprx/", 0666);

	if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0xC445FA63, 0x01360661, (uintptr_t *)&_ksceKernelMountBootfs) < 0)
	if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0x185FF1BC, (uintptr_t *)&_ksceKernelMountBootfs) < 0)
		return SCE_KERNEL_START_FAILED;

	if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0xC445FA63, 0x9C838A6B, (uintptr_t *)&_ksceKernelUmountBootfs) < 0)
	if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0xBD61AD4D, (uintptr_t *)&_ksceKernelUmountBootfs) < 0)
		return SCE_KERNEL_START_FAILED;

	if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0xC445FA63, 0xD269F915, (uintptr_t *)&_ksceKernelGetModuleInfo) < 0)
	if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093, (uintptr_t *)&_ksceKernelGetModuleInfo) < 0)
		return SCE_KERNEL_START_FAILED;

	boot_image_extractor();

	return 0;
}


int module_stop(SceSize args, void *argp) {


	return SCE_KERNEL_STOP_SUCCESS;
}
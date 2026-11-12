#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <string.h>
static int is_hex(char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');}
int main(void){
    SetConsoleOutputCP(CP_UTF8);
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32W pe={sizeof(pe)}; DWORD pid=0; SIZE_T bw=0;
    WCHAR exe[]={'D','i','n','g','T','a','l','k','.','e','x','e',0};
    if(Process32FirstW(snap,&pe)) do{
        if(_wcsicmp(pe.szExeFile,exe)==0){
            HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
            if(h){PROCESS_MEMORY_COUNTERS pmc;if(GetProcessMemoryInfo(h,&pmc,sizeof(pmc))&&pmc.WorkingSetSize>bw){bw=pmc.WorkingSetSize;pid=pe.th32ProcessID;}CloseHandle(h);}
        }
    }while(Process32NextW(snap,&pe));
    CloseHandle(snap);
    if(!pid){fprintf(stderr,"no DingTalk\n");return 1;}
    HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if(!h){fprintf(stderr,"open fail\n");return 2;}
    const SIZE_T CH=1<<20; unsigned char*buf=malloc(CH);
    MEMORY_BASIC_INFORMATION mbi; ULONG_PTR a=0; int n=0;
    while(VirtualQueryEx(h,(LPCVOID)a,&mbi,sizeof(mbi))){
        if(mbi.State==MEM_COMMIT&&(mbi.Protect==PAGE_READWRITE||mbi.Protect==PAGE_READONLY||mbi.Protect==PAGE_WRITECOPY)){
            ULONG_PTR rs=(ULONG_PTR)mbi.BaseAddress,re=rs+mbi.RegionSize;
            for(ULONG_PTR q=rs;q<re;q+=CH){
                SIZE_T want=(SIZE_T)((re-q)<CH?(re-q):CH),got=0;
                if(!ReadProcessMemory(h,(LPCVOID)q,buf,want,&got))continue;
                for(SIZE_T i=0;i+40<=got;i++){
                    if(buf[i]=='d'&&memcmp(buf+i,"did:",4)==0&&is_hex(buf[i+4])){
                        int ok=1;for(int m=1;m<32;m++)if(!is_hex(buf[i+4+m])){ok=0;break;}
                        if(ok){
                            char d[34]={0};memcpy(d,buf+i+4,32);
                            /* 上下文：看后面/前面有什么 */
                            char ctx[80]={0}; SIZE_T k=i+4+32, c=0;
                            while(k<got&&c<60&&buf[k]>=0x20&&buf[k]<0x7f)ctx[c++]=buf[k++];
                            /* 前 40 字节 */
                            char pre[80]={0}; SIZE_T ps=(i>40)?i-40:0,pn=0;
                            for(SIZE_T z=ps;z<i&&pn<60;z++)pre[pn++]=(buf[z]>=0x20&&buf[z]<0x7f)?buf[z]:'.';
                            fprintf(stderr,"[%d] %s\n    pre=\"%s\"\n    post=\"%s\"\n",n++,d,pre,ctx);
                        }
                    }
                }
            }
        }
        a=(ULONG_PTR)mbi.BaseAddress+mbi.RegionSize;
        if(a<(ULONG_PTR)mbi.BaseAddress)break;
    }
    free(buf);CloseHandle(h);return 0;
}

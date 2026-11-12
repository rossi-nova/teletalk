#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>
static int find_pid(void){
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe={sizeof(pe)};DWORD best=0;SIZE_T bw=0;
    if(Process32First(snap,&pe))do{
        if(_stricmp(pe.szExeFile,"DingTalk.exe")==0){
            HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
            if(h){PROCESS_MEMORY_COUNTERS pmc;if(GetProcessMemoryInfo(h,&pmc,sizeof(pmc))&&pmc.WorkingSetSize>bw){bw=pmc.WorkingSetSize;best=pe.th32ProcessID;}CloseHandle(h);}
        }
    }while(Process32Next(snap,&pe));
    CloseHandle(snap);return best;
}
static int lo_hex(char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}
int main(void){
    SetConsoleOutputCP(CP_UTF8);
    DWORD pid=find_pid();
    if(!pid){fprintf(stderr,"no DingTalk\n");return 1;}
    HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if(!h){fprintf(stderr,"open fail\n");return 2;}
    const SIZE_T CH=1<<20;unsigned char*buf=malloc(CH);
    MEMORY_BASIC_INFORMATION mbi;ULONG_PTR a=0;int n=0;
    while(VirtualQueryEx(h,(LPCVOID)a,&mbi,sizeof(mbi))){
        if(mbi.State==MEM_COMMIT&&(mbi.Protect==PAGE_READWRITE||mbi.Protect==PAGE_READONLY||mbi.Protect==PAGE_WRITECOPY)){
            ULONG_PTR rs=(ULONG_PTR)mbi.BaseAddress,re=rs+mbi.RegionSize;
            for(ULONG_PTR q=rs;q<re;q+=CH){
                SIZE_T want=(SIZE_T)((re-q)<CH?(re-q):CH),got=0;
                if(!ReadProcessMemory(h,(LPCVOID)q,buf,want,&got))continue;
                for(SIZE_T i=0;i+36<got;i++){
                    if(buf[i]=='d'&&memcmp(buf+i,"did:",4)==0&&
                       buf[i+4]>='a'&&buf[i+4]<='f'){
                        int ok=1;
                        for(int m=1;m<32;m++)if(!lo_hex(buf[i+4+m])){ok=0;break;}
                        if(!ok)continue;
                        /* dump -2048 .. +512 around, printable view, 128/line */
                        SIZE_T s=(i>2048)?i-2048:0;
                        SIZE_T e=(i+512<got)?i+512:got;
                        fprintf(stderr,"=== did hit %d @0x%llx (off %zu) ===\n",n,(unsigned long long)(q+i),i);
                        for(SIZE_T k=s;k<e;k+=120){
                            for(SIZE_T z=k;z<k+120&&z<e;z++){
                                unsigned char c=buf[z];
                                fputc((c>=0x20&&c<0x7f)?c:0x2E,stderr);
                            }
                            fputc(0x0A,stderr);
                        }
                        if(++n>=2)goto done;
                    }
                }
            }
        }
        a=(ULONG_PTR)mbi.BaseAddress+mbi.RegionSize;
        if(a<(ULONG_PTR)mbi.BaseAddress)break;
    }
done:
    free(buf);CloseHandle(h);return 0;
}

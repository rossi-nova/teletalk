/* 扫描钉钉进程内存里的 LWP 请求帧（明文头），打印指定 URI 的 body */
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
int main(int argc,char**argv){
    SetConsoleOutputCP(CP_UTF8);
    const char *want = argc>1?argv[1]:"getMessageByIdWithCidV2";
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
                SIZE_T want2=(SIZE_T)((re-q)<CH?(re-q):CH),got=0;
                if(!ReadProcessMemory(h,(LPCVOID)q,buf,want2,&got))continue;
                for(SIZE_T i=0;i+6<got;i++){
                    if(buf[i]=='L'&&memcmp(buf+i,"LWP /",5)==0){
                        /* 找 header 结束 \n\n */
                        SIZE_T e=i;int found=0;
                        while(e<got&&e-i<800){if(buf[e]==0x0A&&e+1<got&&(buf[e+1]==0x0A||buf[e+1]==0x2E)){found=1;break;}e++;}
                        if(!found)continue;
                        /* URI 里是否含 want */
                        int hit=0;
                        for(SIZE_T k=i;k<e&&!hit;k++)
                            if(k+strlen(want)<got&&memcmp(buf+k,want,strlen(want))==0)hit=1;
                        if(!hit)continue;
                        fprintf(stderr,"=== req #%d @0x%llx ===\n",n++,(unsigned long long)(q+i));
                        for(SIZE_T k=i;k<e;k++){unsigned char c=buf[k];fputc((c>=0x20&&c<0x7f)?c:0x2E,stderr);}
                        fputc(0x0A,stderr);
                        /* 取 len: 头 */
                        SIZE_T bodyLen=0;
                        for(SIZE_T k=i;k<e;k++){
                            if(k+5<e&&memcmp(buf+k,"len:",4)==0){
                                bodyLen=0;
                                for(SIZE_T z=k+4;z<e&&buf[z]>='0'&&buf[z]<='9';z++)bodyLen=bodyLen*10+(buf[z]-'0');
                                break;
                            }
                        }
                        fprintf(stderr,"body len=%zu hex:",bodyLen);
                        for(SIZE_T k=e+2;k<got&&k<e+2+bodyLen&&k<e+2+200;k++)fprintf(stderr,"%02x",buf[k]);
                        fputc(0x0A,stderr);
                        if(n>=6)goto done;
                    }
                }
            }
        }
        a=(ULONG_PTR)mbi.BaseAddress+mbi.RegionSize;
        if(a<(ULONG_PTR)mbi.BaseAddress)break;
    }
done:
    if(!n)fprintf(stderr,"未找到 %s 的请求帧\n",want);
    free(buf);CloseHandle(h);return 0;
}

#include <iostream>
#include <fstream>
#include <sstream>
#include <list>
#include <algorithm>
#include <asm/unistd.h>
#include <utility>
#include <assert.h>

#include "pin.H"
#include "z3++.h"

//----------------------------------

KNOB<std::string> KnobTaintFile(KNOB_MODE_WRITEONCE, "pintool", "taint-file", "none", "Taint file name");

class TaintedManager
{
    enum
    {
        RAX = 0,
        EAX,
        AX,
        AH,
        AL,

        RBX,
        EBX,
        BX,
        BH,
        BL,

        RCX,
        ECX,
        CX,
        CH,
        CL,

        RDX,
        EDX,
        DX,
        DH,
        DL,

        RDI,
        EDI,
        DI,
        DIL,

        RSI,
        ESI,
        SI,
        SIL,

        NON, //cannot be tainted
    };

  public:
    TaintedManager() : reg_tainted(NON, false) {}
    void taintReg(REG reg)
    {
        taintReg_help(reg, true);
    }

    void removeTaintedReg(REG reg)
    {
        taintReg_help(reg, false);
    }

    void taintMemory(UINT64 addr)
    {
        if (!isMemoryTainted(addr))
            memory_tainted.push_back(addr);
    }

    void removeTaintedMemory(UINT64 addr)
    {
        memory_tainted.remove(addr);
    }

    bool isMemoryTainted(UINT64 addr)
    {
        return std::find(memory_tainted.begin(), memory_tainted.end(), addr) != memory_tainted.end();
    }

    bool isRegTainted(REG reg)
    {
        return reg_tainted[convert(reg)];
    }

    UINT64 getRegID(REG reg)
    {
        int i = convert(reg);
        if (i == RAX || i == EAX || i == AX || i == AL || i == AH)
            return regIDS[0];
        else if (i == RBX || i == EBX || i == BX || i == BL || i == BH)
            return regIDS[1];
        else if (i == RCX || i == ECX || i == CX || i == CL || i == CH)
            return regIDS[2];
        else if (i == RDX || i == EDX || i == DX || i == DL || i == DH)
            return regIDS[3];
        else if (i == RDI || i == EDI || i == DI || i == DIL)
            return regIDS[4];
        else if (i == RSI || i == ESI || i == SI || i == SIL)
            return regIDS[5];
        else
            return 0;
    }

    VOID setRegID(REG reg, UINT64 id)
    {
        int i = convert(reg);
        if (i == RAX || i == EAX || i == AX || i == AL || i == AH)
            regIDS[0] = id;
        else if (i == RBX || i == EBX || i == BX || i == BL || i == BH)
            regIDS[1] = id;
        else if (i == RCX || i == ECX || i == CX || i == CL || i == CH)
            regIDS[2] = id;
        else if (i == RDX || i == EDX || i == DX || i == DL || i == DH)
            regIDS[3] = id;
        else if (i == RDI || i == EDI || i == DI || i == DIL)
            regIDS[4] = id;
        else if (i == RSI || i == ESI || i == SI || i == SIL)
            regIDS[5] = id;
    }

  private:
    int convert(REG reg)
    {
        switch (reg)
        {
        case REG_RAX:
            return RAX;
        case REG_EAX:
            return EAX;
        case REG_AX:
            return AX;
        case REG_AH:
            return AH;
        case REG_AL:
            return AL;
            break;

        case REG_RBX:
            return RBX;
        case REG_EBX:
            return EBX;
        case REG_BX:
            return BX;
        case REG_BH:
            return BH;
        case REG_BL:
            return BL;
            break;

        case REG_RCX:
            return RCX;
        case REG_ECX:
            return ECX;
        case REG_CX:
            return CX;
        case REG_CH:
            return CH;
        case REG_CL:
            return CL;
            break;

        case REG_RDX:
            return RDX;
        case REG_EDX:
            return EDX;
        case REG_DX:
            return DX;
        case REG_DH:
            return DH;
        case REG_DL:
            return DL;
            break;

        case REG_RDI:
            return RDI;
        case REG_EDI:
            return EDI;
        case REG_DI:
            return DI;
        case REG_DIL:
            return DIL;
            break;

        case REG_RSI:
            return RSI;
        case REG_ESI:
            return ESI;
        case REG_SI:
            return SI;
        case REG_SIL:
            return SIL;
            break;

        default:
            return NON;
        }
    }

    void taintReg_help(REG reg_t, bool flag)
    {
        switch (reg_t)
        {
        case REG_RAX:
            reg_tainted[RAX] = flag;
        case REG_EAX:
            reg_tainted[EAX] = flag;
        case REG_AX:
            reg_tainted[AX] = flag;
        case REG_AH:
            reg_tainted[AH] = flag;
        case REG_AL:
            reg_tainted[AL] = flag;
            break;

        case REG_RBX:
            reg_tainted[RBX] = flag;
        case REG_EBX:
            reg_tainted[EBX] = flag;
        case REG_BX:
            reg_tainted[BX] = flag;
        case REG_BH:
            reg_tainted[BH] = flag;
        case REG_BL:
            reg_tainted[BL] = flag;
            break;

        case REG_RCX:
            reg_tainted[RCX] = flag;
        case REG_ECX:
            reg_tainted[ECX] = flag;
        case REG_CX:
            reg_tainted[CX] = flag;
        case REG_CH:
            reg_tainted[CH] = flag;
        case REG_CL:
            reg_tainted[CL] = flag;
            break;

        case REG_RDX:
            reg_tainted[RDX] = flag;
        case REG_EDX:
            reg_tainted[EDX] = flag;
        case REG_DX:
            reg_tainted[DX] = flag;
        case REG_DH:
            reg_tainted[DH] = flag;
        case REG_DL:
            reg_tainted[DL] = flag;
            break;

        case REG_RDI:
            reg_tainted[RDI] = flag;
        case REG_EDI:
            reg_tainted[EDI] = flag;
        case REG_DI:
            reg_tainted[DI] = flag;
        case REG_DIL:
            reg_tainted[DIL] = flag;
            break;

        case REG_RSI:
            reg_tainted[RSI] = flag;
        case REG_ESI:
            reg_tainted[ESI] = flag;
        case REG_SI:
            reg_tainted[SI] = flag;
        case REG_SIL:
            reg_tainted[SIL] = flag;
            break;

        default:
            reg_tainted[NON] = flag;
        }
    }
    std::list<UINT64> memory_tainted;
    std::vector<bool> reg_tainted;
    //0 is invalid
    UINT64 regIDS[6] = {
        0, //ras
        0, //rbx
        0, //rcx
        0, //rdx
        0, //rdi
        0  //rsi
    };

    //reg id
    UINT64 uniqueID;
};

REG getHighReg(REG reg)
{
    switch (reg)
    {
    case REG_RAX:
    case REG_EAX:
    case REG_AX:
    case REG_AH:
    case REG_AL:
        return REG_RAX;

    case REG_RBX:
    case REG_EBX:
    case REG_BX:
    case REG_BH:
    case REG_BL:
        return REG_RBX;

    case REG_RCX:
    case REG_ECX:
    case REG_CX:
    case REG_CH:
    case REG_CL:
        return REG_RCX;

    case REG_RDX:
    case REG_EDX:
    case REG_DX:
    case REG_DH:
    case REG_DL:
        return REG_RDX;

    case REG_RDI:
    case REG_EDI:
    case REG_DI:
    case REG_DIL:
        return REG_RDI;

    case REG_RSI:
    case REG_ESI:
    case REG_SI:
    case REG_SIL:
        return REG_RSI;

    default:
        return REG_AL; /* hack exception */
    }
}
//global vars
//tainted memory and variable manager
TaintedManager tainted_mgr{};

//out put file stream
std::ofstream outfs;

//global flags
//global expr id
UINT64 uniqueID = 1;

//is last syscall is open
bool isLastOpen = false;

//use a list to store since file can be opened multi times
std::list<UINT64> target_file_fd;

//--------------------------------------------------------------------------

//-------------------------------------------------------------------------
//smt,z3 related vars
z3::context z3_context;
//store all constrant expr on memory
//uniqueid starts from 1 this vector starts form 0
std::vector<z3::expr> z3_exprs;
//the serial we need to know
z3::expr target_expr = z3_context.bool_const("x");

char goodSerial[32] = {0};
unsigned int offsetSerial = 0;
//-------------------------------------------------------------------------
//all instrument functions
//insStr instrument in string
VOID ReadMem(UINT64 insAddr, std::string insStr, UINT32 opCount, REG reg_r, UINT64 memAddr)
{
    //we only want to inspect mov instruction
    if (opCount != 2)
        return;
    //compiled on ubuntu 18.04 with g++ 8.1
    //  a9d:	83 bd e0 fe ff ff 04 	cmpl   $0x4,-0x120(%rbp)
    //  aa4:	7f 47                	jg     aed <main+0xf4>
    //  aa6:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax  |
    //  aad:	0f b6 00             	movzbl (%rax),%eax        | move serial.txt char to eax
    //  ab0:	83 f0 55             	xor    $0x55,%eax
    //  ab3:	89 c2                	mov    %eax,%edx
    //  ab5:	48 8b 05 54 15 20 00 	mov    0x201554(%rip),%rax        # 202010 <serial>
    //  abc:	0f b6 00             	movzbl (%rax),%eax
    //  abf:	38 c2                	cmp    %al,%dl
    //  ac1:	74 07                	je     aca <main+0xd1>
    //  ac3:	b8 00 00 00 00       	mov    $0x0,%eax
    //  ac8:	eb 5e                	jmp    b28 <main+0x12f>
    //  aca:	48 83 85 e8 fe ff ff 	addq   $0x1,-0x118(%rbp)
    //  ad1:	01
    //  ad2:	48 8b 05 37 15 20 00 	mov    0x201537(%rip),%rax        # 202010 <serial>
    //  ad9:	48 83 c0 01          	add    $0x1,%rax
    //  add:	48 89 05 2c 15 20 00 	mov    %rax,0x20152c(%rip)        # 202010 <serial>
    //  ae4:	83 85 e0 fe ff ff 01 	addl   $0x1,-0x120(%rbp)
    //  aeb:	eb b0                	jmp    a9d <main+0xa4>
    //we can see from the code that serial is mov to register eax
    //then xor it with 0x55 and then cmp with dl and we can see program want two value to be equal
    //so we build z3 eq start with move ins end with cmp ins
    //the code only compare the al and dl, we could impelement the code to check how many bytes is compared,
    //but in this code we just assume serial is compared each 8 bits
    //we assign each

    //check whether memory address is tainted
    if (tainted_mgr.isMemoryTainted(memAddr))
    {
        std::cout << std::hex << "[READ in " << memAddr << "]\t" << insAddr << ": " << insStr << std::endl;
        std::cout << "[Constraint]\t\t"
                  << "#" << std::dec << REG_StringShort(reg_r) << " = 0x" << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<UINT64>(*(reinterpret_cast<char *>(memAddr))) << std::endl;

        //tainted the register
        tainted_mgr.taintReg(reg_r);
        std::cout << "[Tainted]\t" << REG_StringShort(reg_r) << " is now tainted\n";

        //create a new constrant on this memory
        //as we already know the serial is in hex
        std::stringstream ss;
        //each id is in #id format
        ss << "#" << uniqueID;
        tainted_mgr.setRegID(reg_r, uniqueID++);
        //
        target_expr = z3_context.bv_const(ss.str().c_str(), 64);
        z3_exprs.push_back(target_expr);
    }
}
VOID WriteMem(UINT64 insAddr, std::string insStr, UINT32 opCount, REG reg_r, UINT64 memAddr)
{
    //check whether is a move
    if (opCount != 2)
        return;

    //check whether reg tainted
    //reg not tainted, remove tainted memory
    if (!tainted_mgr.isRegTainted(reg_r) && tainted_mgr.isMemoryTainted(memAddr))
    {
        tainted_mgr.removeTaintedMemory(memAddr);
        std::cout << "[Freed]\t"
                  << "memory " << memAddr << " is now freed\n";
        return;
    }
    else if (tainted_mgr.isRegTainted(reg_r) && !tainted_mgr.isMemoryTainted(memAddr))
    {
        tainted_mgr.taintMemory(memAddr);
        std::cout << "[Tainted]\t"
                  << "memory " << memAddr << " is now Freed\n";
    }
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w, CONTEXT *ctxt)
{
    //check whether is a move
    if (opCount != 2)
        return;
    if (!REG_valid(reg_w))
        return;

    //put not tainted value into a tainted register
    if (tainted_mgr.isRegTainted(reg_w) && (!REG_valid(reg_r) || !tainted_mgr.isRegTainted(reg_r)))
    {
        std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
        tainted_mgr.removeTaintedReg(reg_w);
        tainted_mgr.setRegID(reg_w, 0);
    }
    //put tainted value into a not tainted register
    else if (!tainted_mgr.isRegTainted(reg_w) && tainted_mgr.isRegTainted(reg_r))
    {
        std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: " << REG_StringShort(reg_r) << std::endl;
        //std::cout << "[Constraint]\t\t" << "#" << uniqueID << " = #" << getRegID(reg_r) << std::endl;
        tainted_mgr.taintReg(reg_w);
        tainted_mgr.setRegID(reg_w, tainted_mgr.getRegID(reg_r));
    }
    //put tainted value into a tainted register
    else if (tainted_mgr.isRegTainted(reg_w) && tainted_mgr.isRegTainted(reg_r))
    {
        std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
        std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: " << REG_StringShort(reg_r) << std::endl;
        tainted_mgr.setRegID(reg_w, tainted_mgr.getRegID(reg_r));
    }
}

VOID xorRegReg(REG reg_l, REG reg_r, std::string insDis)
{
    //xor a tainted register with a tainted reg
    if (tainted_mgr.isRegTainted(reg_l) && tainted_mgr.isRegTainted(reg_r))
    {
        std::cout << "[XOR REG REG] " << insDis << "\n";
        //get the id and update the constrant
        UINT64 id_l = tainted_mgr.getRegID(reg_l);
        UINT64 id_r = tainted_mgr.getRegID(reg_r);
        assert(id_l != 0 && id_r != 0);

        z3_exprs[id_l - 1] = z3_exprs[id_l - 1] ^ z3_exprs[id_r - 1];
    }
}

VOID xorRegImm(REG reg_l, UINT64 imm, std::string insDis)
{
    //xor a tainted register with immediate value
    if (tainted_mgr.isRegTainted(reg_l))
    {
        std::cout << "[XOR REG IMM] " << insDis << "\n";
        //get the id and update the constrant
        UINT64 id_l = tainted_mgr.getRegID(reg_l);
        assert(id_l != 0);

        z3_exprs[id_l - 1] = z3_exprs[id_l - 1] ^ static_cast<int>(imm);
    }
}

VOID cmpRegReg(REG reg_l, REG reg_r, CONTEXT *ctx)
{
    z3::solver s(z3_context);
    if (!tainted_mgr.isRegTainted(reg_l))
    {
        if (tainted_mgr.getRegID(reg_r) != 0)
        {
            //solve the equation
            s.add(z3_exprs[tainted_mgr.getRegID(reg_l)] == z3_exprs[tainted_mgr.getRegID(reg_r)]);
            s.check();
        }
        else
        {
            s.add(z3_exprs[tainted_mgr.getRegID(reg_l)] == static_cast<int>(PIN_GetContextReg(ctx, getHighReg(reg_r))));
        }

        assert(s.check() == z3::check_result::sat);

        z3::model m = s.get_model();
        std::cout << "[Z3 Solver]-------------------------------------" << std::endl;
        unsigned int goodValue;

        Z3_get_numeral_uint(z3_context, target_expr, &goodValue);
        std::cout << "The good value is 0x" << std::hex << goodValue << std::endl;
        goodSerial[offsetSerial++] = goodValue;
        std::cout << "[Z3 Solver]-------------------------------------" << std::endl;
    }
}

VOID cmpRegImm(REG reg_l, UINT64 imm)
{
    if (!tainted_mgr.isRegTainted(reg_l))
        return;

    z3::solver s(z3_context);
    s.add(z3_exprs[tainted_mgr.getRegID(reg_l)] == static_cast<int>(imm));

    z3::model m = s.get_model();
    std::cout << "[Z3 Solver]-------------------------------------" << std::endl;
    unsigned int goodValue;

    Z3_get_numeral_uint(z3_context, target_expr, &goodValue);
    std::cout << "The good value is 0x" << std::hex << goodValue << std::endl;
    goodSerial[offsetSerial++] = goodValue;
    std::cout << "[Z3 Solver]-------------------------------------" << std::endl;
}

//-------------------------------------------------------------------------
VOID Syscall_entry(THREADID threadIndex, CONTEXT *ctxt,
                   SYSCALL_STANDARD std, VOID *v)
{

    if (PIN_GetSyscallNumber(ctxt, std) == __NR_open)
    {
        //check is going to open target file

        std::string filename(reinterpret_cast<char *>(PIN_GetSyscallArgument(ctxt, std, 0)));

        if (filename == KnobTaintFile.Value())
        {
            isLastOpen = true;
        }
    }
    else if (PIN_GetSyscallNumber(ctxt, std) == __NR_close)
    {
        //remove the closed file desc
        UINT64 fd = PIN_GetSyscallArgument(ctxt, std, 0);
        target_file_fd.remove(fd);
    }
    else if (PIN_GetSyscallNumber(ctxt, std) == __NR_read)
    {
        UINT64 fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctxt, std, 0)));
        UINT64 start = static_cast<UINT64>((PIN_GetSyscallArgument(ctxt, std, 1)));
        UINT64 size = static_cast<UINT64>((PIN_GetSyscallArgument(ctxt, std, 2)));

        if (std::find(target_file_fd.begin(), target_file_fd.end(), fd) == target_file_fd.end())
            return;
        //tainted memory
        for (UINT64 i = 0; i < size; ++i)
            tainted_mgr.taintMemory(start + i);
        //show some msg
        std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start + size << " (via read)" << std::endl;
    }
}

VOID Syscall_exit(THREADID thread_id, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    if (isLastOpen)
    {
        //get the file desc and push it to the list
        target_file_fd.push_back(PIN_GetSyscallReturn(ctxt, std));
        isLastOpen = false;
    }
}
//-------------------------------------------------------------------------

VOID Instruction(INS ins, VOID *v)
{
    if (INS_OperandCount(ins) <= 1)
        return;

    //read memory into reg
    if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0))
    {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE,
            (AFUNPTR)ReadMem,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_UINT32, INS_OperandReg(ins, 0),
            IARG_MEMORYOP_EA, 0,
            IARG_END);
    }
    //from reg to memory
    else if (INS_MemoryOperandIsWritten(ins, 0))
    {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE,
            (AFUNPTR)WriteMem,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_UINT32, INS_OperandReg(ins, 1),
            IARG_MEMORYOP_EA, 0,
            IARG_END);
    }
    //from reg or constant to reg
    //this function is only used to spread tainted, not to edit constrant on any of reg
    else if (INS_OperandIsReg(ins, 0))
    {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_UINT32, INS_RegR(ins, 0),
            IARG_UINT32, INS_RegW(ins, 0),
            IARG_CONTEXT,
            IARG_END);
    }

    //all math operation
    //xor reg,reg
    if (INS_Opcode(ins) == XED_ICLASS_XOR && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1))
    {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)xorRegReg,
            IARG_UINT32, INS_OperandReg(ins, 0),
            IARG_UINT32, INS_OperandReg(ins, 1),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_END);
    }
    //xor reg,immediate
    else if (INS_Opcode(ins) == XED_ICLASS_XOR && INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1))
    {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)xorRegImm,
            IARG_UINT32, INS_OperandReg(ins, 0),
            IARG_ADDRINT, INS_OperandImmediate(ins, 1),
            IARG_END);
    }
    //cmp reg,reg
    else if (INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1))
    {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)cmpRegReg,
            IARG_UINT32, INS_OperandReg(ins, 0),
            IARG_UINT32, INS_OperandReg(ins, 1),
            IARG_CONTEXT,
            IARG_END);
    }
    //cmp reg,imm
    else if (INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1))
    {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)cmpRegImm,
            IARG_UINT32, INS_OperandReg(ins, 0),
            IARG_ADDRINT, INS_OperandImmediate(ins, 1),
            IARG_END);
    }
}

INT32 Usage()
{
    cerr << "This tool resolve simple crack me" << endl;
    cerr << endl
         << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID writeSerial(INT32 code, VOID *v)
{
    outfs.close();
    //update the target file content

    FILE *trace;

    trace = fopen(KnobTaintFile.Value().c_str(), "w");
    fprintf(trace, "%s", goodSerial);
    fclose(trace);

    return;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv))
        return Usage();

    outfs.open("taint_memory.out");
    if (!outfs.is_open())
    {
        std::cout << "Can't create out file" << std::endl;
        return 1;
    }

    //Sets the disassembly syntax to Intel format. (Destination on the left)
    PIN_SetSyntaxIntel();

    PIN_AddSyscallEntryFunction(Syscall_entry, 0);

    // Register Fini to be called when the application exits
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(writeSerial, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

# The Art of Software Security Assessment
John McDonald, Justin Schuh, and Mark Dowd

## Contents

- [ ] Part 1: Introduction to Software Security Assessment
    - [x] Chapter 1: Software Vulnerability Fundamentals
    - [ ] Chapter 2: Design Review
- [ ] Part 2: Software Vulnerabilities
    - [ ] Memory Corruption
	
- [ ] Part 3: Software Vulnerabilities in Practice

## Tips
- You'll get the most value if you read this book straight through at least
  once so that you can get a feel for the material.
- In particular, you should pay attention to the sidebars and notes we use
  to sum up the more important concepts in a section.

## Part 1: Introduction to Software Security Assessment
### Chapter 1: Software Vulnerability Fundamentals

**Bugs** are errors, mistakes, or oversights in programs that result in
unexpected and typically undesirable behavior.

**Vulnerabilities** are specific flaws or oversights in a piece of software
that allow attackers to do something maliciousexpose or alter sensitive
information, disrupt or destroy a system, or take control of a computer
system or program.

**Exploiting** is the process of attacking a vulnerability in a program.

**Exploit** is an external program or script to perform an attack.

**Security Policy** defines a system's security, it is simple a list of
what's allowed and what's forbidden. From this perspective, a violation of
a software system's security occurs when the system's security policy is
violated.

#### Security Expectations
- Confidentiality
- Integrity
- Availability

**Auditing** an application is the process of analyzing application code
(in source or binary form) to uncover vulnerabilities that attackers might
exploit.

**Black box testing** is a method of evaluating a software system by
manipulating only its exposed interfaces.

**Fuzz-testing** is the process of automated black box testing. It includes
generic "dumb" and protocol-aware "intelligent" fuzzers.

#### Systems Development Life Cycle (SDLC)

1. Feasibility study
2. Requirements definition
3. Design
4. Implementation
5. Integration and testing
6. Operation and maintenance

**Vulnerability classes** are sets of vulnerabilities that share some
unifying commonality, a pattern or concept that isolates a specific feature
shared by several different software flaws.

#### Vulnerability classes
1. Design vulnerabilities ```(SDLC 1,2,3)```
2. Implementation Vulnerabilities ```(SDLC 4,5)```
3. Operational Vulnerabilities ```(SDLC 6)```

#### Common Threads
1. Input and Data Flow
2. Trust Relationships
  - Transitive nature of trust: if your software system trusts a particular
    external component, and that component in turn trusts a certain
    network, your system has indirectly placed trust in that network.
3. Assumptions and Misplaced Trust
4. Interfaces
5. Environmental Attacks
6. Exceptional Conditions

### Chapter 2 - Design Review

```
Computer security people tend to fall into one of two camps on design
review. People from a formal development background are usually receptive
to the design review process.

In the other camp are code auditors who delight in finding the most obscure
and complex vulnerabilities.
```

#### Software Design Fundamentals

**Problem domain logic** (or business logic) provides rules that a program
follows as it processes data.

**Abstraction** is a method for reducing the complexity of a system to make
it more manageable.

**Decomposition** (or factoring) is the process of defining the
generalizations and classifications that compose an abstraction.

- Top-down decomposition, known as specialization, is the process of
  breaking a larger system into smaller, more manageable parts.
- Bottom-up decomposition, called generalization, involves identifying the
  similarities in a number of components and developing a higher-level
  abstraction that applies to all of them.

**Chain of Trust**

**Defense in depth** is the concept of layering protections so that the
compromise of one aspect of a system is mitigated by other controls.

**Accuracy** refers to how effectively design abstractions meet the
associated requirements.

**Coupling** refers to the level of communication between modules and the
degree to which they expose their internal interfaces to each other.

**Cohesion** refers to a module's internal consistency.

#### Fundatmental design flaws
##### Exploiting Strong Coupling

- Shatter class of vulnerabilities by Chris Paget.
- Solaris ```automountd``` and ```rpc.statd```

##### Failure Handling

Usability and security are occasionally at odds. A developer might decide
not to give feedback on an error as errors are caused by attackers and
proper error handling and diagnosing information would help the attacker in
understanding the underlying details.

#### Enforcing Security Policy

```
TBD
```

## Part 2: Software Vulnerabilities
### Chapter 1: Memory Corruption

**Assumption:** all memory corruption vulnerabilities should be treated as
exploitable until you can prove otherwise.

Exploit creation and software auditing are two differentbut highly
complementary skill sets.

#### Further reading

- The Shellcoder's Handbook by Jack Koziol et al.
- Exploiting Software by Greg Hoglund and Gary McGraw
- Phrack <http://www.phrack.org/>
- Uninformed <http://www.uninformed.org/>

#### Buffer Overflows

**Buffer overflow** is a software bug in which data copied to a location in
memory exceeds the size of the reserved destination area.

##### Stack overflows

**Stack overflows** are buffer overflows in which the target buffer is
located on the runtime program stack.

**Note:** Usually, functions are called before ```main()``` to set up the
environment for the process. For example, glibc Linux systems usually begin
with a function named ```_start()```, which calls ```_libc_start_main()```,
which in turn calls ```main()```.

Local variables need to be accessed directly as the function requires them,
which would be inefficient just using push and pop instructions. Therefore,
many programs make use of another register, called the "frame pointer" or
"base pointer." On Intel x86 CPUs, this register is called EBP (EBP stands
for "extended base pointer"). The use of the base pointer is optional, and
it is sometimes omitted.

##### Function-Calling Conventions

A calling convention describes how function parameters are passed to a
function and what stack maintenance must be performed by the calling and
called functions.

A popular optimized x86 calling convention is the fastcall. The fastcall
passes function parameters in registers when possible, which can speed up
variable access and reduce stack maintenance overhead.

##### Function Prologue

```
mov edi,edi ; placeholder added to ease runtime patching for system monitoring and debugging
push ebp
mov ebp,esp
```

##### SEH attacks

- Windows is vulnerable to **structured exception handling** attacks.
- SEH is provided so that errors can be handled in a consistent manner.
- There is a chain of such handlers.
- When an exception is thrown, the chain is traversed from the top until
  the correct handler type is found for the thrown exception.
- If no such handler is found, the exceptions is passed to an "unhandled
  exception filter" which generally terminates the process.
- C++ exceptions in Windows are implemented on top of SEH.
  <http://www.openrce.org/articles/full_view/21>
- Therefore if there is a stack-overflow vulnerability:
	- An exception occurs due to the overwritten base address.
    - The application jumps to an address of the attackers choosing through
      the overwritten exception handler.

```
           +--------------------------------------------------+      _
       .---|   pointer to previous _EXCEPTION_REGISTRATION    |      |
       |   +--------------------------------------------------+      |
       |   |                 SEH handler #3                   |      |
       |   +--------------------------------------------------+      |    current stack frame
       |   |                                                  |      |
       |   +--------------------------------------------------+      |
       |   |                                                  |      |
       |   +--------------------------------------------------+      ^
       `-> |   pointer to previous _EXCEPTION_REGISTRATION    |---.
           +--------------------------------------------------+   |
           |                 SEH handler #2                   |   |
           +--------------------------------------------------+   |
           |                                                  |   |
           +--------------------------------------------------+   |
           |                                                  |   |
           +--------------------------------------------------+   |
           |   pointer to  _EXCEPTION_REGISTRATION(-1)        |<--'
           +--------------------------------------------------+
           |                 SEH handler #1                   |
           +--------------------------------------------------+

```

<http://www.openwall.com/advisories/OW-002-netscape-jpeg/>

#### Off-by-One Errors

```
int get\_user(char \*user)
{
	char buf[1024];
	if(strlen(user) > sizeof(buf))
		die("error: user string too long\n");
	strcpy(buf, user);
...
}
```

- `strlen()` counts everything apart from `\0`.
- OSes running on Intel x86 machines are off-by-one exploitable.
- You can overwrite the least significant byte of the saved frame pointer.
- If the overwritten base pointer points to user-controllable data, program
  is pwned.
- Off-by-one can also overwrite adjacent variables.

#### Heap Overflows

<http://www.openwall.com/advisories/OW-002-netscape-jpeg/>

- `malloc()` memory is fetched and returned to the user.
- `free()` memory is deallocated => the system must mark it as free.
- This state information is stored inline, a block is returned to the user.

Block

- Size of current block
- Size of previous block
- Whether the block is free or in use
- Some additional flags

<http://phrack.org/issues/57/9.html>

Standard attack technique:

1. Free blocks have pointers to next and previous blocks in the free chunks list.
2. When a block is freed, it is coalesced with adjacent blocks.
3. Merge: removes next chunk, adjusts chunk being freed to reflect bigger size, adds new larger chunk to free list.
4. Attacker overflows heap to mark the next chunk as free so that it's later unlinked from the list.
5. We use the overflown buffer to list pointer in the corrupted chunk to useful locations.
6. During the unlink, an arbritrary write is performed. Why?

```
int unlink(ListElement *element) {

	ListElement *next = element->next;
	ListElement *prev = element->prev;

	next->prev = prev;
	prev->next = next;

	return 0;
}
```

Arbritrary overwrite is usually all that is required to own the process.
- GOT / PLT: used to dynamically resolve functions in UNIX ELF binaries
- Exit handlers: table of function pointers called when a process exits in
  UNIX
- Lock pointers: set of function pointers in the process environment block
  (PEB)
- Exception handler routines: address for unhandled exception filter
  routind in Windows PEB.

#### Shellcode

`TBD`

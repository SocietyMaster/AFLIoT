## 针对Fuzz的Patch

### 为何使用Patch

目前的Fuzz策略采用了AFL，AFL运行基于程序的分支覆盖率信息，需要获得程序运行时的路径信息，所以就需要对程序的运行进行某种形式的记录。AFL中存在两种模式，即有源码情况下通过afl-gcc或者afl-clang-fast编译，以及无源码情况下的QEMU模式。在源码编译的模式下，AFL主要会对条件跳转的非跳转分支入口、函数入口、所有跳转的目的入口进行插桩，在这些地方插入记录路径的代码从而达到记录程序运行路径的目的，其中afl-gcc通过对汇编文件进行解析决定在何处插入桩代码，仅支持x86架构，而afl-clang-fast则是在llvm的IR层面增加了一个pass，与后端架构无关。而在QEMU执行模式下，AFL通过模拟器来模拟执行目标程序，并对跳转指令注册回调来记录执行路径，这种方式对于原二进制文件没有任何更改。

对于IoT设备，大多数情况下无法获取到源码，这时候就可以有三种不同的方式来做。

第一个是将源程序整个反汇编，然后向afl-gcc所做的一样在汇编层面插入桩代码，最后再汇编回去。这个工作极度依赖于反汇编器的准确性，如果反汇编器可以识别出程序中所有的代码和数据，保证可以将函数指针的访问、数据的引用等还原到汇编前的水平，那就可以通过这个办法来插桩，最后得到的插桩完的程序只会有轻微的性能损失。但是实际上，现在可用的反汇编器基本无法达到这个要求，对于大型的复杂程序，反汇编器往往只能作为逆向工程的辅助工具，实际中有相当大的概率会在反汇编的过程中丢失原有的代码和数据，这使得反汇编再汇编的操作会破坏源程序的逻辑完整性，甚至导致完全无法运行。

第二个方法是保持程序的完整性，在二进制层面上进行Fuzz，借助AFL自带的QEMU模式在QEMU模拟器中模拟执行对应的二进制，并在跳转指令处执行回调来记录程序执行的路径，这种方法避免了对程序的分析，能够记录下最完整的路径信息。在x86平台的大型服务器上，因为性能强大，QEMU模式有比较好的可用性，但是在IoT设备上往往无法达到性能要求，所以在这里我们也不能使用这个方法。

所以我们采用的是第三种方案，即把记录路径的代码直接在二进制层面Patch的形式插桩到程序中，通过对源程序直接Patch的方式，保留了原程序的所有代码和数据结构，避免对源程序的执行逻辑的破坏。观察AFL在源码情况下的插桩，其实等价于对程序中所有的Basic Block进行插桩，我们通过反汇编器识别出程序中的Basic Block，对每一个Basic Block都插入对应的桩代码。因为反汇编器能力的限制，很可能存在不能识别出的Basic Block，但是跟第一种方案不同的是，这个时候我们只是丢失了部分Basic Block的执行信息，不能对其进行跟踪，造成精度的下降，而不会对程序本身的执行造成影响。所以反汇编器的能力影响的是我们插桩的精度，对于正确性没有影响。而二进制层面的Patch也避免了模拟器执行的额外开销，将程序的执行速度提高到了与源代码编译插桩相当的级别，实际测试中有10%左右的性能损失。

### AFL部分Patch

具体Patch工作由elfpatcher部分说明，这里是上层说明。

#### afl初始化

在afl-clang-fast的pass中有afl初始化共享内存和启动forkserver的函数，直接采用这几个函数并单独编译成so，然后在目标程序中导入so文件和初始化函数的符号，并在目标程序的init_array中插入初始化函数来执行afl初始化，这样目标程序在启动之后就会有interpreter来负责初始化afl，随后的执行可以反映到共享内存中。

#### 插桩代码

afl记录路径采用的方法可以归纳为如下的代码：

```c
__thread short afl_prev_loc = 0;
unsigned char afl_shm_area[MAP_SIZE];

void afl_log(short cur_loc) {
	afl_shm_area[afl_prev_loc ^ cur_loc] += 1;
	afl_prev_loc = cur_loc >> 1;
}
```

其中：

+ cur_loc为当前Basic Block的id
+ afl_prev_loc为上一个执行到的Basic Block的id右移1位的结果，初始为0
+ afl_shm_area为记录程序执行路径的数组

当程序执行到某个Basic Block记录点时，桩代码就会将afl_prev_loc和cur_loc的亦或结果作为afl_shm_area的index，并将对应的计数器加一，通过计数器的状态可以保持对程序执行路径的跟踪。

这个记录的代码比较高效，翻译成ARM时避免函数调用等复杂操作，对于每一个Basic Block的插桩代码如下：

```
stmfd sp!, {r0 - r4}
ldr r0, =afl_prev_loc_tls_offset
ldr r1, [r0]
mrc p15, 0, r0, c13, c0, 3
ldrh r2, [r0, r1]
movw r4, #0xdead
eor r2, r2, r4
ldr r3, =shm_pointer
ldr r3, [r3]
ldrb r4, [r3, r2]
add r4, r4, #1
strb r4, [r3, r2]
movw r2, #0xdead >> 1
strh r2, [r0, r1]
ldmfd sp!, {r0 - r4}
```

因为afl_prev_loc是线程变量，需要使用到thread local storage，所以需要先给程序添加（如果原来存在则需要扩展）TLS存储的空间，然后将TLS变量的offset重定位到afl_prev_loc_tls_offset变量中，这里需要elfpatcher的支持。在实际桩代码中，只需要从协寄存器中取出TLS的地址并加上偏移即可访问afl_prev_loc。

### Server程序的Hook

AFL设计针对的目标大多数是文件解析类的程序，这里程序会通过标准输入或者是文件接收一个输入，AFL则通过对文件的变异来实现对这些程序的Fuzz。而在IoT设备上，除了类似于传统的这类程序之外，还存在着大量的服务程序，这类服务程序以Server的形式运行，监听某一个端口并从网络接收输入，这种情况是AFL无法直接处理的，所以需要对这类目标程序进行额外的处理使AFL可以Fuzz此类程序。

一个思路是保持AFL和程序原来的执行逻辑不变，模拟设立另一个client，当AFL启动了新的实例时，由在程序中插入的桩代码通知client，而后client读取AFL已经修改过的输入文件，并通过网络途径发送给程序。如此对于Server程序原先的逻辑几乎没有改动，只是通过client在AFL和程序中做了一层透明的代理，使AFL以为的文件输入转换成网络输入，实现对目标的Fuzz。但是具体实现之后发现，这样的操作流程避免不了需要Server去bind端口并且accept新连接，client也需要去连接目标端口，而这些网络操作都是相当费时的，这造成了对于Server的Fuzz性能下降非常厉害。

所以最后我们采用的方式是hook全部socket族的函数，在底层直接拦截网络操作，并将标准输入输出映射到原先的网络操作，从而实现了AFL对Server程序的Fuzz，并且避免了大量耗时的网络操作。

首先，我们会提供一个明确的端口号，程序在这个端口上的操作都会被映射到标准输入输出上，之所以需要对端口进行区分，是因为程序可能监听了不止一个端口，如果对所有的端口都进行映射，而AFL这头只有一个输入，则不同端口对输入的访问就会产生竞争，也就不能对程序的特定逻辑进行稳定的fuzz，而指定端口则可以避免这个问题。

bind时需要提供端口参数，则在bind时我们可以知道该socket是否为我们的目标socket，hook会在bind操作之后拦截下后续操作，创建一对socketpair用作全双工的管道，并创建两个线程来实现输入输出的转发。具体而言，对于socket族函数的hook大抵分为三个部分：

+ 对基础socket函数诸如socket、bind、listen、accept、close等的hook
+ 对用户态输入事件的事件型函数诸如select、poll等的hook
+ 对内核态注册事件的epoll系列函数诸如epoll_create、epoll_ctl、epoll_wait等的hook

#### hook基础socket函数

socket函数负责创建socket file descriptor，因为在创建socket的时候我们并不知道这个socket是否是我们的目标socket，所以我们的hook不对其进行拦截，但是会将其使用的type参数记录下来，以便在后续socketpair创建时使用。

bind操作时端口号作为参数传了进来，此时我们就可以确定是否进行拦截，如果拦截则记录下目标的socket fd，记为bind_fd，并且拦截下bind直接返回成功。

在accept时，如果目标是我们确定的bind_fd则需要进行拦截，具体是如下几步：

+ 创建一对与socket相同type的socketpair，记两头分别是A、B
+ 创建两个线程分别对stdin->B以及B->stdout进行转发
+ 返回A作为accept_fd

程序后续会将file descriptor A作为正常accept返回的fd进行读写操作，而管道另一头两个线程会将stdio上的数据映射到B上，A也就可以访问到相应的数据。

close函数需要判断fd是否为accept_fd，如果是则意味着程序已经完成本地连接的处理，则可以直接退出当前程序以通知AFL启动下一个实例。

listen函数如果是对bind_fd进行操作，则直接返回成功，因为我们实际上没有对bind_fd进行bind操作，所以listen(bind_fd)会失败。

setsockopt用于对socket设置属性，在一般情况下，我们不需要hook它，但是在我们的拦截生效之后，程序依旧认为这个socket是一个accept返回的普通socket，但实际上已经被我们替换成了socketpair的一端，那么setsockopt很可能已经将产生意料之外的效果，所以我们就拦截下来相关的设置直接返回成功。

#### hook select/poll

基础socket族函数的hook已经可以保证stdio与socket之间的映射了，但是程序并不是都是按照基础函数来操作的，select/poll系列函数（包括pselect和ppoll）可以通过用户态传入一系列的fd，然后由内核监听这一系列fd，只要有一个及以上的fd出现ready的状态，或者到达timeout就会直接返回。

因为我们的hook在bind时进行了拦截并没有真的进行bind，如果程序对bind_fd进行select或者poll，是不会收到事件通知的，所以如果hook检测到bind_fd位于select或者poll的监听列表中，则主动从列表中去除这一项，然后对剩下的fd进行正常监听，并在返回时手动为bind_fd加上事件通知，以此来模拟有新连接到达的事件。

#### hook epoll系列函数

除了用户态的select/poll系列函数可以用来监听fd之外，linux还提供了epoll系列函数，程序可以通过epoll_create在内核中创建一个监听队列，而后通过epoll_ctl往这个监听队列中添加新的fd以及对应的事件，或者是修改、删除。最后通过epoll_wait对整个队列进行监听。

与select/poll类似的，bind_fd在此处也不会产生事件通知，程序就有可能在epoll_wait时阻塞，所以需要在hook中将bind_fd对应的事件首先从内核中删除掉，对余下的fd进行监听，并在返回时加上bind_fd对应的事件通知。所不同的在于，epoll系列允许程序为每个fd附带一个64位的任意数据，此数据会在事件触发时原样返回，所以我们还需要hook epoll_create和epoll_ctl函数，将所有对epoll的操作都模拟记录下来，从而在返回bind_fd对应事件时可以返回正确的数据信息。

### Daemon程序的Hook

IoT设备中还存在部分Daemon程序，此类程序通过fork/setsid/fork的流程从命令行对应的session中脱离出来，保证程序一直运行在后台。此类程序在AFL的fuzz过程中，因为父进程在fork马上就退出了，会使AFL误认为程序已经自然结束，从而启动了新的实例，Fuzz在这种情况下无法进行。所以对于这类程序需要对这两种函数进行hook，在fork中直接返回0模拟子进程的情况。除此之外，libc还提供了daemon函数用于相同的功能，也需要一起hook。

### 库文件的Patch

某些程序使用了第三方库来解析数据包，或者主要逻辑都在共享库中，主程序的逻辑异常简单，对此类程序的Fuzz必须对其使用的库进行插桩，否则程序中根本没有多少路径信息，也就无法对Fuzz进行指导。对so的插桩与普通ELF的插桩基本一致，同样导入用于对AFL进行初始化的so，并对所有Basic Block进行插桩即可，具体PIE支持由elfpatcher说明。插桩完之后只需要将目标程序的lib路径定位到插桩后的so，就可以实现同时记录ELF本身与so文件路径的功能，实现对lib内部逻辑的Fuzz。

## ELF-Patcher

一个普通的ELF文件大体结构如下：

| ELF Format |
| ------ |
| ELF header |
| Program header table |
| Section No.1 |
| Section No.2 |
| ... |
| Section No.N |
| Section header table |

其中ELF header指定了ELF的基本信息，比如指令集、版本号、是32位还是64位，是可执行文件还是动态库，另外还指定了Program header table和Section header table的位置大小信息。Program header table指定了程序运行时信息，比如PT_LOAD项指定了文件中数据与内存区块的映射关系，PT_DYNAMIC指定了.dynamic节的位置大小等。Section header table指定了程序中所有Section的位置、大小、权限等信息，这些信息在链接时是有用的。而Section则是保存具体数据的地方，包括代码段、数据段等。对于一个用来执行的ELF而言，Section header table是可以省略的，而对于用来链接Link的ELF而言，Program header table是可以省略的。但是一般情况下，一个ELF会同时保留这两者。

Patch希望让程序执行新的代码，但是原来的代码段在编译之后就不再有多余的空间放新的代码，所以Patch的思路只能是在ELF中插入新的Section，将Patch使用的代码和数据全部放在这些Section中，然后修改原有的代码段，使得Patch的位置跳转到新插入的代码，完成插桩之后再跳转回到原来的代码里。这样需要做的事情主要有三件：

+ 为Patch的数据和代码插入新的Section，同时在Section header table插入新的项
+ 在Program header table中插入新的PT_LOAD段来保证新的数据代码会被加载到内存中
+ 修改原有的.text段中的代码，在Patch处跳转到对应的Patch代码，并执行被跳转指令覆盖的指令

### 插入Section

插入新的Section是最简单的，首先确定好新插入的数据的长度，然后在原文件所有的Section之后直接插入新的数据，即可确定新Section的地址和大小，然后在Section header table的后面插入一项指定新的Section的地址、偏移、大小等信息即可。这样对其他Section都不会造成影响，只要移动并扩展Section header table，而后者的位置大小信息位于ELF header中，相对应修改即可。

对于插入的新的Patch代码，需要汇编之后才知道代码需要占用的空间，而只有在知道占用的空间之后才能确定Section如何排布，从而知道原来代码中访问的相对偏移是多少，才可以汇编出正确的代码，这就形成了一个环。解决方法是先假定一个地址进行编译，获取到代码的具体长度，在所有代码全部插入完成之后，将Section的地址固定下来，最后再次根据新的地址重新汇编并更新原来的代码，所以对于每一段代码都需要在插入时，以及最后所有都插入完成后两次汇编。

### 更新Program header table

Section是静态链接时的信息，单纯插入Section并不能让数据和代码在运行时被加载到内存中，相对应的需要让Program header table中存在对应Section的PT_LOAD项，以指定将ELF中的某一段数据以何种权限加载到内存中的什么地址。

插入新的项到Program header table意味着其体积会变大，但是因为Program header table的后面紧跟着Section的具体数据，直接扩展两者数据就会有重叠。所以只有两个解决方案，一个是将Program header table整体移动到后面空闲的区域，第二个是将Program header table后面的Section移动到后面。

对于第一个方案，将Program header table移动到所有Section后面的空闲区域，根据ELF Specification只需要修改ELF header中Program header table相关的e_phoff及e_phnum即可，但是实际上这个方案并不可行，因为在Linux kernel的代码中，多处直接假定Program header table紧跟在ELF header的后面，而不是根据e_phoff来定位，这样移动Program header table就会造成内核找不到Program header table，从而程序根本无法启动。
```c
phdr_ptr = (Elf32_Phdr*)(elfptr + sizeof(Elf32_Ehdr)); /* PT_NOTE hdr */
```

所以实际上我们只能使用第二个方案，通过对大量ELF的统计，紧跟在Program header table之后并且我们可以移动的几个Section有：

+ .interp section，指定程序interpreter的路径，Program header table中的PT_INTERP项指定
+ .note.* section，程序附加的各种note信息，由Program header table中的PT_NOTE项指定
+ .hash section，保存了程序中符号的哈希表，由dynamic段中的DT_HASH项指定
+ .gnu.hash section，保存了程序中符号的哈希表，由dynamic段中的DT_GNU_HASH项指定
+ .dynsym section，程序中所有的符号信息，由dynamic段中的DT_SYMTAB项指定
+ .dynstr section，保存了.dynsym节所使用的字符串信息，由dynamic段中的DT_STRTAB和DT_STRSZ项指定

这些Section都是通过Program header table或者dynamic段来定位，不存在其他硬编码的访问，所以移动只需要更新对应的指针即可，另外内部数据也都不涉及相对偏移的访问，移动不会造成程序执行的问题。这些Section不是每一个ELF都会出现，但是每一个ELF都至少会有其中数个Section出现，如果对出现过的所有Section都进行移位，就足以空出足够大的空间容纳扩展后的Program header table。

移动Section之后，我们就可以根据插入的Section的情况给Program header table插入新的项。这里需要注意的是，这里讲的插入的Section不仅仅是我们插入的Section，也包括上面移动的Section，因为这些Section被移动之后就不在属于原来的某一个PT_LOAD加载的区域，所以也需要新的PT_LOAD来处理它们。将插入的Section根据权限可以分成只读、读写、可执行三种权限，根据权限排布所有的Section，然后分别根据大小和偏移插入PT_LOAD项即可将数据加载到内存中。

### 修改原.text代码

ARM为RISC指令集，每个指令都是4字节对齐，也就不存在指令之间不等长的问题，所以Patch任何一处都只需要将原来的指令直接替换成一条跳转指令，跳转到目标Patch指令并执行，再执行原来被Patch掉的指令并跳回原来的指令后面一条即可。

```
     +
     |
     v
+----+-----+ PATCH +----------+       +---------+
|  insn_a  | +---> |  branch  | +---> |  patch  |
+----------+       +----------+       |  code   |
|  insn_b  | <----------+             +----+----+
+----+-----+            |                  v
     |                  |             +----+-----+
     v                  |             |  insn_a  |
                        |             +----+-----+
                        |                  v
                        |             +----+-----+
                        +-------------+  branch  |
                                      +----------+
```

在这个过程中，一个需要考虑的问题是，如何让insn_a在新的位置正常的执行？

正常执行有两个方面，第一个是不能对其他寄存器或者是内存产生破坏，第二个是指令其本身的功能要达到。不能产生破坏意味着如果我们要使用内存，就只能使用当前sp以下的栈空间，因为这里是默认目前不被使用的。而对于第二点，直接把原来的指令汇编在新的位置存在一定的问题，比如`ldr r1, [pc, #0x10]`这条指令，在新的位置pc的值已经不同于原来的位置，那么这句话就会出错。我们比较两种情况，唯一的区别就是pc在新旧两处的值是不同的，那么对于这些依赖于pc值的指令我们就需要消除这种差别。

所以在这里我将整个ARM指令集大体上分成5类：

+ 完全不依赖PC的指令，如不涉及PC的计算指令、内存访问指令，或者将不涉及PC的值写入PC的
+ 跳转指令，虽然依赖于PC，但是在指令中以相对偏移来编码，或者是直接使用寄存器
+ 以PC为源头的指令，从PC中，或者相对于PC取偏移的位置取值，赋值到其他位置
+ 以PC为源头，并且涉及到栈操作的指令
+ 以PC为源头，同时也涉及到对PC写入的指令

对于这5种不同的指令，分别可以给出4种不同的wrap方案。

#### 不依赖或者跳转

这种情况包含了以上5类指令中的前两类。

对于完全不依赖PC的指令，在何处执行并不影响其执行结果，所以只需要将其简单拷贝到新的位置并执行即可。

而对于跳转指令，有寄存器和相对偏移两种不同的情况。如果其使用了寄存器，则寄存器的值在进入到Patch代码时就将是正确的值，不需要进行调整。如果其使用了相对偏移，则我们反汇编原来的指令时就可以获得目的地址，以新的相对偏移来汇编就可以使其跳转到正确的地址，这个过程可以在反汇编到汇编的过程中自动完成，也不需要额外的调整。

所以综上，只需要将目标指令简单复制过来，并在后面添加一条跳转回源地址后一条指令的指令即可：

```
original_instruction,
b original_instruction_vaddr + 4
```

#### PC为源

这种情况处理了第三种指令，即以PC为源头，从PC中，或者相对于PC取偏移的位置取值，赋值到其他位置。

这种情况的处理策略为：

+ 在所有可用寄存器中找到一个目标指令没有使用过的寄存器，作为pivot
+ 将pivot寄存器原来的值保存到栈中，并将其赋值成源指令执行时PC的值，即original_instruction_vaddr+8
+ 将目标指令中的所有pc寄存器替换成pivot寄存器，这样目标指令就可以正常执行
+ 执行完成之后，弹栈将pivot寄存器恢复成原来的值
+ 跳转回原来的后一条指令

具体的wrap指令为：

```
stmdb sp, {pivot}       					
ldr pivot, =original_instruction_vaddr + 8 	
pc_replaced_original_instruction          	
ldmdb sp, {pivot}       					
b original_instruction_vaddr + 4
```

#### PC为源，并涉及到栈操作

这种情况处理上面的第四种指令，与第三种指令不同的是，这种指令涉及到了栈的操作，这使得第三种指令对应的wrap代码可能出现问题，因为我们依赖于栈来保存pivot寄存器，所以对这种指令需要使用不同的wrap方案。

通过对大量ARM ELF Binary的统计，发现这种指令只有两种不同的形态：

+ push {other_registers, pc}
+ stmfd sp!, {other_registers, pc}

而其实这两种形态是同一种操作，就是将一系列寄存器（包含pc寄存器）压栈，只是机器码有所不同。在ARM中，将一系列寄存器压栈时，寄存器会按照寄存器编号的高低依次排布在内存的高低位置，与具体指令书写无关，而pc寄存器对应第16号通用寄存器，拥有最大的编号。所以当这类指令执行时，pc会被放在整个压栈操作的最高点，下面其他寄存器的序列并不影响这个结果。

据此，我们可以将PC与其他寄存器的压栈分离，具体操作如下：

+ 同样挑选一个没有使用到的寄存器作为pivot，调整sp将pivot原来的值压入堆栈，此时pivot被保存在(源sp-8)的位置
+ 将pivot赋值成源指令执行时PC的值，即original_instruction_vaddr+8，并保存到(源sp-4)的位置，相当于执行了push {pc}
+ 从(源sp-8)的位置弹出并恢复pivot的值，将sp调整到(源sp-4)
+ 将剩下的所有寄存器正常压入栈中，跳转回原来的后一条指令

对应的wrap代码如下：

```
sub sp, sp, 4               				
stmdb sp, {pivot}       					
ldr pivot, =original_instruction_vaddr + 8 	
stmia sp, {pivot}       					
ldmdb sp, {pivot}       					
push {other_registers}               		
b original_instruction_vaddr + 4
```

wrap时我们需要直接可以保存pivot寄存器的地方，这里将pc跟其它寄存器分开处理可以提供一个确定的位置（即源sp-8）来保存pivot寄存器。当然也可以用不同的方法，比如统计整个push将消耗多少栈空间，然后将pivot保存到整个消耗的空间的下方，这样也可以避免push操作与保存的pivot产生覆盖。

#### PC为源，并写入PC

这种情况处理了上面的第五类指令，这种指令与上面的几种不同之处在于，其执行完成之后就会写入PC，这个写入操作会造成跳转的效果，如果我们使用了pivot并且在执行指令前保存到了栈上，那么一旦这条指令被执行，我们就失去了对代码的控制，而没有机会去恢复pivot，这就会干扰程序原先的状态和继续执行。所以我们需要给出一个在跳转时同时恢复pivot的wrap方案。

同样通过统计，发现这种指令只在switch jump的时候出现，具体有两种形式：

+ ldr pc, [pc, reg, lsl#2]
+ add pc, pc, reg, lsl#2

第一种是指令后跟随着一张jump table，从jump table中取出目标代码指针直接跳转，第二种则是在当前指令之后跟随了一批branch指令，通过跳转到这些branch指令再进一步跳转到不同的目标代码。前者在普通ELF中较为常用，后者则更多出现于开启了PIE支持的ELF中。

对这种指令的wrap方案如下：

+ 挑选一个没有使用到的寄存器作为pivot，调整sp将pivot原来的值压入堆栈，此时pivot被保存在(源sp-8)的位置
+ 将pivot赋值成源指令执行时PC的值，即original_instruction_vaddr+8
+ 将源指令中的pc全部替换成pivot，包括目标与源，并且执行，此时pivot会被写入即将跳转的目的PC值
+ 调整sp，并将当前pivot压入堆栈，此时pivot被保存在(源sp-4)的位置
+ 从(源sp-8)的位置pop {pivot, pc}，其中pc将从高处取出，pivot从低处取出，同时实现恢复pivot和跳转的目的

在这种情况下我们无需在最后跳转回原来的位置，因为本身已经存在跳转。相对应的代码如下：

```
sub sp, sp, 4               				
stmdb sp, {pivot}      						
add sp, sp, 4               				
ldr pivot, =original_instruction_vaddr + 8
pc_replaced_original_instruction
stmdb sp, {pivot}      					 	
ldmdb sp, {pivot, pc}  					 	
```

#### condition

以上几种方案已经可以囊括一般ELF中的所有可能情况，大规模测试中没有出现遗漏。

有一点注意的是，ARM中大部分指令都可以带一个condition code，表示在特定条件下才执行。对于上面的头两种方案并没有影响，因为我没有更改原来的指令，但是后两种里我变相的代为执行了原来指令中的部分功能，如第三种中的push {pc}和第四种中最后的跳转，所以还需要在这两种的开头插入判断，如果条件不符即可直接跳回源指令的后一句，而无需执行wrap部分的代码。

### init_array

对于目标程序，我们往往找不到其程序入口main，或者对于一个共享库，其根本不存在main入口，这个时候如果希望在程序加载的时候优先执行某些初始化函数，比如AFL中用来得到shared memory以及启动fork server的init函数，就需要通过在init_array中注册回调，由interpreter来调用。

init_array是一个Section，由dynamic段中的DT_INIT_ARRAY和DT_INIT_ARRAYSZ项来指定，本身内容为一个数组，其中每一项都是一个指向某一个初始化函数的函数指针。一个直观的方法是直接改写这个数组，并更新dynamic段内的信息，但是实际上gcc在这里取了个巧，gcc编译的程序并不通过dynamic段里的信息来调用init_array中的回调函数，而是直接硬编码了init_array在程序中的偏移和大小，这使得扩展和移动init_array的方法变得不可能。

所以这里采用的方法是，

+ 插入一段类似于libc_csu_init的代码，用于循环调用回调函数指针数组，数组地址在新的数据段
+ 替换原init_array数组的最后一项为上一步插入的代码
+ 将原init_array数组的最后一项，以及所有新添加的回调函数组成的数组，放在第一步中的新数据段里

如此在程序本身调用最后一项初始化时，同时完成新增的初始化操作，插入的stub如下：

```
    stmfd sp!, {r3 - r6, lr}
    stmfd sp!, {r0 - r2}
    ldr r5, =init_array_offset
    ldr r6, =init_array_count
    eor r4, r4, r4
nextcall:
    ldmfd sp, {r0 - r2}
    ldr r3, [r5], #4
    blx r3
    add r4, r4, 1
    cmp r4, r6
    bne nextcall
    add sp, sp, 0xc
    ldmfd sp!, {r3 - r6, pc}
```

### PIE支持

IoT设备中的ELF可执行文件默认往往被编译成没有PIE的版本，而共享库文件则必须支持基地址随机化，所以对于共享库的插桩就需要针对PIE进行特殊的支持。开启PIE支持的程序与一般的ELF的区别就在于程序运行时，其基地址是不确定的，当程序被loader加载到一个基地址时，程序中原本存在的、编译时就已经确定的指针就需要进行重定位，loader需要将其修改成当前基地址加上编译时确定的偏移所得的真实虚拟地址，防止程序运行时取到错误的指针。这种重定位由relocation节中类型为R_ARM_RELATIVE的项来完成。

在我们Patch之前，程序中存在的重定位项一定覆盖了所有需要重定位的地址，这是编译器的工作，而我们在Patch的时候，对程序的修改就会引入新的需求，主要有三个可能的来源：

+ 对数据section的移动或者修改导致需要重定位
+ 对原程序中的代码的Patch需要重定位
+ 新插入的代码和数据需要重定位

第一种情况，对数据section的移动或者修改是在我们对init_array进行扩展的时候，此时需要对新插入的init_array数组中的每一项都进行重定位，旧的init_array数组已经存在重定位则无需考虑。

第二种情况，如果原程序中的代码涉及到重定位，并且我们的Patch（跳转到桩代码的指令）更改了代码，就需要删除掉原先的重定位项并在新的位置进行重定位。但是非常幸运的是，ARM指令集的指令长度统一为4字节，而R_ARM_RELATIVE重定位项的功能是将4字节的内存进行重定位加上运行时的基地址，这意味着对某一个指令进行重定位是不可能出现的，否则指令会被破坏，那么就不用考虑这种情况的出现。实际上ARM中的重定位多出现在数据指针上，而我们的Patch方案中不涉及数据的移动和修改，所以第二种情况可以不考虑。

最后一种情况对象是新插入的代码和数据，包括了插入的指针数据，这比较直观，以及插入代码中对于其他符号的引用。在ARM中，对其他符号进行引用往往采用类似`ldr reg, =symbol_address`的形式，这种指令会被翻译成ldr指令加上4字节的数据，我们就需要对这4字节的数据进行重定位，此时需要计算出这4字节在指令序列中的偏移。但同时我们又要避免对类似于`ldr reg, =const`这类指令的重定位，因为其对应的数据并不是一个指针。为此，elfpatcher需要首先对整个插桩过程中出现的所有符号进行记录，在插桩保存时对所有插入的代码进行比较，找到符号被引用的地方并依次对这些数据进行重定位。

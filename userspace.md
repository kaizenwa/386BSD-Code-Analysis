## Walkthrough of FreeBSD 1's _init_ Process

Since I cannot locate the init source file for 386BSD 0.1, I will be
using FreeBSD 1's init source file instead. I am assuming that they
are pretty much the same thing since the init source file has nothing
to do with underlying hardware.

### Contents

1. Code Flow
3. Source Code Commentary

### Code Flow

```txt
```

### Source Code Commentary

#### main (freebsd-1.0/sbin/init/init.c:151) 

```txt
167: Calls setsid.

170: Calls signal to setup the signal handler for SIGHUP.

171: Calls signal to setup the signal handler for SIGTSTP.

173-176: Calls signal to ignore the SIGTTIN, SIGTTOU, SIGCHLD,
         and SIGINT signals.

191: Calls saccess on /etc/rc.

201: Child calls revoke on /dev/console.

204: Child calls login_tty on /dev/console.

205: Child calls execl on /bin/sh, passing /etc/rc as an
     argument. The last command in rc is "exit 0", which
     causes the child process to exit with the status of 0.

208: Parent sets Reboot to zero.

209: Parent calls wait.

212-213: Parent calls pause if the child received SIGKILL.

214: Parent calls logwtmp.

Note: The parent process init is executing the rest of the code
      since the child process that executed rc exited with a
      status of 0.

243: Calls setttyent.

244-248: Initializes the entries in the ttytab (line 81) using /etc/ttys.

250: Assigns the current value of tt to ttyabend.

251: Calls endttyent.

252: Calls getty for each entry in the ttytab.

313: Sets the drain global variable to zero.
```

#### setsid (386bsd-0.1/sys/kern/kern\_prot.c:172)

```txt
Control Flow:
main
    setsid <-- Here

181: Calls enterpgrp.
```

#### enterpgrp (386bsd-0.1/sys/kern/kern\_proc.c:97)

```txt
Control Flow:
main
    setsid
        enterpgrp <-- Here
```

#### signal (386bsd-0.1/usr/src/lib/libc/gen/signal.c:46)

```txt
Control Flow:
main
    setsid
    signal <-- Here
```

#### saccess (386bsd-0.1/sys/kern/vfs\_syscalls.c:973)

```txt
Control Flow:
main
    setsid
    signal
    saccess <-- Here (child)
```

#### revoke (386bsd-0.1/sys/kern/vfs\_syscalls.c:1741)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    revoke <-- Here (child)
```

#### login\_tty (386bsd-0.1/usr/src/lib/libutil/login\_tty.c:41)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    revoke
    login_tty <-- Here (child)

44: Calls setsid.

45: Calls ioctl on /dev/console to set it as the controlling terminal.

47-49: Calls dup2 to create STDIN, STDOUT, and STDERR.
```

#### execl (386bsd-0.1/usr/src/lib/libc/gen/exec.c:86)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    revoke
    login_tty
    execl <-- Here (child)
```

#### rc (freebsd-1.0/etc/rc:10)

```txt
17: Exports root directory as HOME variable.

18-19: Exports /sbin:/bin:/usr/sbin:/usr/bin as the PATH variable.

60: Runs swapon -a to make all devices in /etc/fstab available for
    paging and swapping.

79-82: Runs /etc/rc.serial scrip to configure serial devices.

86: Runs /etc/netstart to turn on the network.

97: Runs syslogd.

...

238: Runs the rc.local script.
```

#### rc.local (freebsd-1.0/etc/rc.local:7)

```txt
```

#### setttyent (386bsd-0.1/usr/src/lib/libc/gen/getttyent.c:177)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    setttyent <-- Here


181: Calls rewind if tf already points to a file.

183: Calls fopen to open /etc/ttys as a read-only file.
```

#### endttyent (/386bsd-0.1/usr/src/lib/libc/gen/getttyent.c:189)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    setttyent
    gettyent
    endttyent <-- Here

193-197: Calls fclose on tf if it points to a file and returns rval.
```

#### getty (freebsd-1.0/sbin/init/init.c:344)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    setttyent
    gettyent
    endttyent
    getty <-- Here

354: Calls fork to create a child process.

356-360: Parent process returns early.

         Note: How does this work? The fork call assigns two return
               values to tt->tt_pid, so wouldn't that cause a race
               condition?

               I suppose I should study 386BSD's fork code in-depth
               to find an answer to this. If the child process
               always executes first, then this is really easy to
               understand.

364: Calls sigsetmask.

384: Calls execve to execute /usr/libexec/getty.
```

#### main (freebsd-1.0/libexec/getty/main.c:137)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    setttyent
    getttyent
    endttyent
    getty
        main <-- Here

237: Calls getname.

250: Calls ioctl to set the TIOCSLTC option.

251-252: Copies pointers from the environ external variable to
         the env global variable.

253: Calls makeenv.

255: Calls execle to create a login shell for the user.
```

#### getname (386bsd-0.1/usr/src/libexec/getty/main.c:288)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    setttyent
    getttyent
    endttyent
    getty
        main
            getname <-- Here

297-301: Initializes the interrupt handler code.

305: Prints the login prompt to the terminal screen.

311: Calls ioctl to set the TIOCSETP option.

314-356: Reads input from STDIN until we either fill the name buffer
         or the user presses enter (corresponds to '\r' || '\n').

365: Returns 1.
```

#### makeenv (/386bsd-0.1/usr/src/libexec/getty/subr.c:376)

```txt
Control Flow:
main
    setsid
    signal
    saccess
    setttyent
    getttyent
    endttyent
    getty
        main
            getname
            makeenv <-- Here
```

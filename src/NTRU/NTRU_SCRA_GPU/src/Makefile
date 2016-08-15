#cuda makefile start
GPUCRYPTO_DIR = ..

####################################################
# OS Name (Linux or Darwin)
OSUPPER = $(shell uname -s 2>/dev/null | tr [:lower:] [:upper:])
OSLOWER = $(shell uname -s 2>/dev/null | tr [:upper:] [:lower:])

# Flags to detect 32-bit or 64-bit OS platform
OS_SIZE = $(shell uname -m | sed -e "s/i.86/32/" -e "s/x86_64/64/")
OS_ARCH = $(shell uname -m | sed -e "s/i386/i686/")

# These flags will override any settings
ifeq ($(i386),1)
	OS_SIZE = 32
	OS_ARCH = i686
endif

ifeq ($(x86_64),1)
	OS_SIZE = 64
	OS_ARCH = x86_64
endif

# Flags to detect either a Linux system (linux) or Mac OSX (darwin)
DARWIN = $(strip $(findstring DARWIN, $(OSUPPER)))

# Location of the CUDA Toolkit binaries and libraries
CUDA_PATH       ?= /usr/local/cuda-6.5
CUDA_INC_PATH   ?= $(CUDA_PATH)/include
CUDA_BIN_PATH   ?= $(CUDA_PATH)/bin
ifneq ($(DARWIN),)
  CUDA_LIB_PATH  ?= $(CUDA_PATH)/lib
else
  ifeq ($(OS_SIZE),32)
    CUDA_LIB_PATH  ?= $(CUDA_PATH)/lib
  else
    CUDA_LIB_PATH  ?= $(CUDA_PATH)/lib64
  endif
endif

# Common binaries
NVCC            ?= $(CUDA_BIN_PATH)/nvcc
GCC             := gcc

# CUDA code generation flags
GENCODE_SM10    := -gencode arch=compute_10,code=sm_10
GENCODE_SM20    := -gencode arch=compute_20,code=sm_20
GENCODE_SM30    := -gencode arch=compute_30,code=sm_30 
GENCODE_FLAGS   :=  $(GENCODE_SM30) 

# OS-specific build flags
ifneq ($(DARWIN),) 
      LDFLAGS   := -Xlinker -rpath $(CUDA_LIB_PATH) -L$(CUDA_LIB_PATH) -lcudart
      CCFLAGS   := -arch $(OS_ARCH) 
else
  ifeq ($(OS_SIZE),32)
      LDFLAGS   := -L$(CUDA_LIB_PATH) -lcudart
      CCFLAGS   := -m32
  else
      LDFLAGS   := -L$(CUDA_LIB_PATH) -lcudart
      CCFLAGS   := -m64
  endif
endif

# OS-architecture specific flags
ifeq ($(OS_SIZE),32)
      NVCCFLAGS := -m32
else
      NVCCFLAGS := -m64
endif
# Debug build flags
ifeq ($(dbg),1)
      CCFLAGS   += -g
      NVCCFLAGS += -g -G
      TARGET    := debug
else
      TARGET    := release
endif


# Common includes and paths for CUDA
NVCCINCLUDES      := -I$(CUDA_INC_PATH) -I. -I/usr/local/cuda-6.5/samples/common/inc/ -I/usr/local/cuda-6.5/samples/common/inc

CU_SRC_FILES = $(wildcard *.cu)

SRC_FILES = $(CU_SRC_FILES) 
OBJS_FILE = $(CU_SRC_FILES:.cu=.o) 

$(OBJS_DIR)/%.o : %.cu
	$(NVCC) -G -g -DMP_USE_64BIT=1 $(NVCCFLAGS) $(GENCODE_FLAGS) $(NVCCINCLUDES) -c $< -o $@


#cuda makefile end
PARAMSETS=433 577 769 1153

# Directories.
TOPDIR = ..
BINDIR = $(TOPDIR)/bin
DATADIR = $(TOPDIR)/data
DIRS = $(BINDIR) $(DATADIR) 

vpath %.dat $(DATADIR)

CFLAGS += -c
#CFLAGS += -Wall
#CFLAGS += -O3 -ffast-math -mtune=native -malign-double

LDFLAGS = -lfftw3 -lm -L$(CUDA_LIB_PATH) -lcudart -lcrypto
#LDFLAGS = -lfftw3 -lm -L$(CUDA_LIB_PATH) -lcudart -lcrypto -lcufft

SOURCES=$(wildcard *.c)  
CU_SRC_FILES = $(wildcard *.cu) #change
OBJECTS=$(SOURCES:.c=.o) $(CU_SRC_FILES:.cu=.o)
CU_OBJ_FILES = $(CU_SRC_FILES:.cu=.o) #change 
EXECUTABLE=$(TOPDIR)/bin/bench


all: dirs wisdom data $(CU_SRC_FILES) $(SOURCES) $(EXECUTABLE)

dirs : $(DIRS)
	mkdir -p $?

# Ensure all FFTW wisdom files exist
wisdom: $(addprefix $(TOPDIR)/data/, $(addsuffix _wisdom.dat, $(PARAMSETS)))
$(TOPDIR)/data/%_wisdom.dat :
	$(BINDIR)/wiseup.sh $*

data: $(addprefix $(TOPDIR)/data/, $(addsuffix _rader.dat, $(PARAMSETS)))
data: $(addprefix $(TOPDIR)/data/, $(addsuffix _perm.dat, $(PARAMSETS)))
data: $(addprefix $(TOPDIR)/data/, $(addsuffix _points.dat, $(PARAMSETS)))
%_rader.dat %_points.dat %_perm.dat:
	$(warning Runtime data for set $* not present ($@). See README.)

$(EXECUTABLE): $(OBJECTS)
	$(GCC) -o $@ $(OBJECTS) $(LDFLAGS)
	
.c.o: %.cc 
	$(GCC) $(CFLAGS) $(CCFLAGS) $(NVCCINCLUDES) $< -o $@

bsparseconv.o: bsparseconv.cu bsparseconv.h 
	$(NVCC) -G -g -DMP_USE_64BIT=1 $(NVCCFLAGS) $(GENCODE_FLAGS) $(NVCCINCLUDES) -c bsparseconv.cu -o bsparseconv.o	
	
.PHONY : clean
clean:
	rm -f $(OBJECTS)
	rm -f $(EXECUTABLE)


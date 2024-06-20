#!/bin/bash

BASEDIR="/path/to/AFLPlusplus"

# Simple tool for Nyx VM image operations (create, configure, create pre_image snapshot)

QEMU_PT_BIN="$BASEDIR/nyx_mode/QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64"
MEMORY_SIZE=6144

error () {
  echo "$0: <Mode>"
  echo ""
  echo "Modes: "
  echo " -  create_image"
  echo " -  install"
  echo " -  post_install"
  echo " -  create_snapshot"
  echo ""
  echo "Debug Modes: "
  echo " -  run_kernel"
  exit 3
}

error_image () {
  echo "$0: create_image <image_name> <size in MB>"
  exit 3
}

error_install () {
  echo "$0: install <image_name> <iso_file>"
  exit 3
}

error_post_install () {
  echo "$0: post_install <image_name>"
  exit 3
}

error_create_snapshot () {
  echo "$0: create_snapshot <image_name> <memory-size> <snapshot_directory>"
  exit 3
}

error_run_kernel () {
  echo "$0: run_kernel <bz_image>"
  exit 3
}

if [ "$#" == 0 ] ; then
  error
fi

if [ "$1" == "create_image" ]; 
then 
  echo CREATE_IMAGE; 
  if [ "$#" != 3 ] ; then
    error_image
  fi

  dd if=/dev/zero of=$2 bs=1048576 count=$3
  exit 0
fi

if [ "$1" == "install" ]; 
then 
  echo INSTALL; 
  if [ "$#" != 3 ] ; then
    error_install
  fi

  NYX_DISABLE_DIRTY_RING=TRUE NYX_DISABLE_BLOCK_COW=TRUE $QEMU_PT_BIN --enable-kvm -drive format=raw,file=$2 -cdrom $3 -k de -vnc :0 -m $MEMORY_SIZE
  exit 0
fi

if [ "$1" == "post_install" ]; 
then 
  echo POST_INSTALL; 
  if [ "$#" != 2 ] ; then
    error_post_install
  fi

  NYX_DISABLE_DIRTY_RING=TRUE NYX_DISABLE_BLOCK_COW=TRUE $QEMU_PT_BIN --enable-kvm -drive format=raw,file=$2 -k de -vnc :0 -m $MEMORY_SIZE -net user,hostfwd=tcp::2222-:22 -net nic
  exit 0
fi

if [ "$1" == "create_snapshot" ]; 
then 
  echo CREATE_SNAPSHOT; 
  if [ "$#" != 4 ] ; then
    error_create_snapshot
  fi

  mkdir $4 && \
  NYX_DISABLE_DIRTY_RING=TRUE $QEMU_PT_BIN --enable-kvm -hda $2 -k de -vnc :0 -m $3 -net none -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1 -fast_vm_reload pre_path=$4,load=off
  exit 0
fi

if [ "$1" == "run_kernel" ]; 
then 
  echo RUN_KERNEL; 
  if [ "$#" != 2 ] ; then
    error_run_kernel
  fi

  SCRIPT=$(readlink -f "$0")
  SCRIPTPATH=$(dirname "$SCRIPT")

  # exit via (ctrl+a) & q
  $QEMU_PT_BIN -kernel $2 -initrd $SCRIPTPATH/linux_initramfs/init_debug_shell.cpio.gz -serial mon:stdio -enable-kvm -k de -m 300 -append "root=/dev/sda console=ttyS0 nokaslr" -nographic
  exit 0
fi

error

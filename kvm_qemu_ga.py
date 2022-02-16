#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @version:    1.0
# @license:    Apache Licence 
# @Filename:   kvm_qemu_ga.py
# @Author:     chaidisheng
# @contact:    chaidisheng@stumail.ysu.edu.cn
# @site:       https://github.com/chaidisheng
# @software:   PyCharm
# @Time:       2022/2/14 22:54
# @torch: tensor.method(in-place) or torch.method(tensor)
r""" docs """

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import sys
import time
import socket
import libvirt
import logging
import argparse
import libvirtmod_qemu

from functools import wraps
from collections import OrderedDict
from logging.handlers import RotatingFileHandler

# virDomainQemuMonitorCommandFlags
VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT = 0
VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP = 1

# virDomainQemuAgentCommandTimeoutValues
VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK = -2
VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN = -2
VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT = -1
VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT = 0


class LoggingInfo(object):
    """
    日志信息记录
    """
    __slots__ = ['log_file', 'log_level', 'log_format']

    def __init__(self, log_level=logging.INFO, log_file="/b_iscsi/log/kvm_qemu-agent.log"):
        self.log_file = log_file
        self.log_level = log_level
        self.log_format = '%(asctime)s %(filename)s (%(funcName)s %(lineno)s) [%(levelname)s] - %(message)s'

    def init_log_format(self):
        """
        设置日志初始化格式
        :return: None
        """
        logging.basicConfig(format=self.log_format, datefmt='%Y-%m-%d %H:%M:%S', level=self.log_level,
                            filename=os.path.join(os.getcwd(), self.log_file))

    def generator_logger(self):
        """
        register loop logger
        :return: logger object
        """
        logger = logging.getLogger(__name__)
        logger.setLevel(level=self.log_level)
        # 定义一个RotatingFileHandler，最多备份3个日志文件，每个日志文件最大1K
        rHandler = RotatingFileHandler(self.log_file, maxBytes=1 * 1024, backupCount=3)
        rHandler.setLevel(level=self.log_level)
        formatter = logging.Formatter(self.log_format)
        rHandler.setFormatter(formatter)
        logger.addHandler(rHandler)
        # lack logger.removeHandler(rHandler)
        return logger

    def __call__(self, func):
        r""" logging decorator
            TODO 预留日志装饰器（函数名称、注释文档、参数列表）
        """
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            logger = logging.getLogger(func.__name__)
            logger.setLevel(self.log_level)
            fh = logging.FileHandler(self.log_file)
            fh.setLevel(self.log_level)
            formatter = logging.Formatter(self.log_format)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            logger.info("step into {0}".format(func.__name__))
            result = func(*args, **kwargs)
            logger.info("step out {0}".format(func.__name__))
            logger.removeHandler(fh)
            return result

        return wrapped_function


# 生成限制大小为1k、备份3次的日志记录对象，避免配置logrotate.conf
logger = LoggingInfo(log_level=logging.ERROR, log_file="/b_iscsi/log/kvm_qemu-agent.log").generator_logger()


class Instance(object):
    """
    获取单个虚拟机信息
    """
    __slots__ = ['name', 'instances', 'instance']

    def __init__(self, name):
        self.name = name
        try:
            # domain must be alive
            self.instances = libvirt.open("qemu:///system")
            self.instance = self.instances.lookupByName(name)
        except libvirt.libvirtError as e:
            logger.error("Failed to open connection to the hypervisor for {0}".format(str(e)))

    def __del__(self):
        self.instances.close()

    def get_xml(self, flag=0):
        return self.instance.XMLDesc(int(flag))

    def get_status(self):
        return self.instance.isActive()

    def attach_device(self, xml, flag=0):
        self.instance.attachDeviceFlags(xml, flag)

    def detach_device(self, xml, flag=0):
        self.instance.detachDeviceFlags(xml, flag)


class QemuGuestAgent(Instance):
    r"""qemu guest agent module"""

    def __init__(self, name):
        super(QemuGuestAgent, self).__init__(name)

    def qemu_monitor_command(self, domain, cmd, flags):
        """Send an arbitrary monitor command through qemu monitor of domain """
        ret = libvirtmod_qemu.virDomainQemuMonitorCommand(domain._o, cmd, flags)
        if ret is None:
            raise libvirt.libvirtError('virDomainQemuMonitorCommand() failed')
        return ret

    def qemu_agent_command(self, domain, cmd, timeout, flags):
        """Send a Guest Agent command to domain {qemu-agent-command}"""
        ret = libvirtmod_qemu.virDomainQemuAgentCommand(domain._o, cmd, timeout, flags)
        if ret is None:
            raise libvirt.libvirtError('virDomainQemuAgentCommand() failed')
        return ret

    def qemu_attach(self, conn, pid_value, flags):
        """This API is QEMU specific, so it will only work with hypervisor
        connections to the QEMU driver.

        This API will attach to an externally launched QEMU process
        identified by @pid. There are several requirements to successfully
        attach to an external QEMU process:

          - It must have been started with a monitor socket using the UNIX
            domain socket protocol.
          - No device hotplug/unplug, or other configuration changes can
            have been made via the monitor since it started.
          - The '-name' and '-uuid' arguments should have been set (not
            mandatory, but strongly recommended)

        To date, the only platforms we know of where pid_t is larger than
        unsigned int (64-bit Windows) also lack UNIX sockets, so the choice
        of @pid_value as an unsigned int should not present any difficulties.

        If successful, then the guest will appear in the list of running
        domains for this connection, and other APIs should operate
        normally (provided the above requirements were honored). """
        ret = libvirtmod_qemu.virDomainQemuAttach(conn._o, pid_value, flags)
        if ret is None:
            raise libvirt.libvirtError('virDomainQemuAttach() failed')
        __tmp = libvirt.virDomain(conn, _obj=ret)
        return __tmp

    def qemu_set_vm_time(self, args):
        """
        虚拟机时间与宿主机同步
        :param args: TODO
        :return: 成功返回0，失败返回-1
        """
        if self.get_status():
            cmd_get_time = '{"execute":"guest-get-time"}'
            try:
                vm_time_stamp = eval(self.qemu_agent_command(self.instance, cmd_get_time,
                                                             timeout=VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT,
                                                             flags=0))
                local_time_stamp = int(time.time() * 1e+9)
                if vm_time_stamp != local_time_stamp:
                    cmd_set_time = '{"execute":"guest-set-time", "arguments":{"time":%d}}' % local_time_stamp
                    ret = eval(self.qemu_agent_command(self.instance, cmd_set_time,
                                                       timeout=VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK,
                                                       flags=0))
                    return 0 if ret["return"] == {} else -1
            except Exception as e:
                logger.error(str(e))
                return -1
        else:
            logger.error("virtual machine {0} is not running".format(self.name))
            return -1

    @LoggingInfo()
    def qemu_guest_agent_socket(self, args):
        """
        需要进一步区别虚拟机，锁机制
        qemu-guest-agent-1.service
        :param args: cmd
        :return:
        """
        serverAddr = '/var/lib/libvirt/qemu/org.qemu.guest_agent.1.instance-00023f5f.sock'
        # unix套接字，tcp通信方式，不支持上下文管理
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(serverAddr)
            sock.sendall(args.cmd)
            print(sock.recv(102400))
            return 0
        except Exception as e:
            logger.error(str(e))
            return 1
        finally:
            sock.close()

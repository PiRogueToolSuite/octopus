// SPDX-FileCopyrightText: 2026 Defensive Lab Agency
// SPDX-FileContributor: u039b <git@0x39b.fr>
//
// SPDX-License-Identifier: GPL-3.0-or-later

import Java from "frida-java-bridge";

function _socket_trace(pid, process) {

    function _send_msg(msg) {
        const _msg = {
            'type': 'socket_traces',
            'dump': 'socket_trace.json',
            'pid': pid,
            'process': process,
            'data_type': 'json',
            'timestamp': Date.now(),
            'data': msg
        }
        send(_msg)
    }

    Process
    .getModuleByName({ linux: 'libc.so', darwin: 'libSystem.B.dylib', windows: 'ws2_32.dll' }[Process.platform])
    .enumerateExports().filter(ex => ex.type === 'function' && ['connect', 'recv', 'send', 'read', 'write'].some(prefix => ex.name.indexOf(prefix) === 0))
    .forEach(ex => {
        Interceptor.attach(ex.address, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const socket_type = Socket.type(fd);
                if (socket_type !== 'tcp' && socket_type !== 'tcp6' && socket_type !== 'udp' && socket_type !== 'udp6')
                    return;
                const dest_addr = Socket.peerAddress(fd);
                if (dest_addr === null)
                    return;
                const local_addr = Socket.localAddress(fd);
                if (local_addr === null)
                    return;
                const socket_info = {
                    socket_fd: fd,
                    socket_type: socket_type,
                    pid: Process.id,
                    thread_id: this.threadId,
                    socket_event_type: ex.name,
                    dest_ip: dest_addr.ip,
                    dest_port: dest_addr.port,
                    local_ip: local_addr.ip,
                    local_port: local_addr.port,
                }
                if (Java.vm !== null && Java.vm.tryGetEnv() !== null) {
                    let java_lang_Exception = Java.use("java.lang.Exception")
                    var exception = java_lang_Exception.$new()
                    const trace = exception.getStackTrace()
                    socket_info.stack = trace.map(trace_elt => {
                      return {
                        class: trace_elt.getClassName(),
                        file: trace_elt.getFileName(),
                        line: trace_elt.getLineNumber(),
                        method: trace_elt.getMethodName(),
                        is_native: trace_elt.isNativeMethod(),
                        str: trace_elt.toString()
                      }
                    })
                  }
                _send_msg(socket_info);
            }
        })
    })
}

export function socket_trace(pid, process) {
    _socket_trace(pid, process);
}

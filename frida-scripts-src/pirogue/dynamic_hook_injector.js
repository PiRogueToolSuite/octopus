// SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
// SPDX-FileCopyrightText: 2026 Defensive Lab Agency
// SPDX-FileContributor: u039b <git@0x39b.fr>
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT
import Java from "frida-java-bridge";

function _inject_hooks(pid, process, hook_list) {
    console.log('Inject dynamic hooks')
    hook_list.forEach(item => {
        item.methods.forEach(method => {
            try {
                const name_split = method.split('/');
                const class_name = name_split.slice(0, -1).join('/').slice(1);
                const method_name = name_split[name_split.length - 1];
                if (method.startsWith('L')) {
                    try {
                        _inject_hook(pid, process, item.taxonomy_id, item.description, class_name, method_name);
                    } catch (error) {}
                }
            } catch (error) {}
        });
    });
}

function _inject_hook(pid, process, taxonomy_id, description, class_name, method_name) {
    function _send_msg(msg) {
        const _msg = {
            message_type: "java_hook_data",
            type: 'dynamic_hook_log',
            dump: 'dynamic_hook.json',
            data_type: 'json',
            pid: pid,
            process: process,
            timestamp: Date.now(),
            data: msg
        }
        send(_msg)
    }

    const target_class = Java.use(class_name);
    const overloads = target_class[method_name].overloads;
    const Exception = Java.use('java.lang.Exception');
    // hook each method's overloads
    overloads.forEach(overload => {
        overload.implementation = function () {
            const timestamp = Date.now();
            try {
                const args = [].slice.call(arguments);
                const returned_value = this[method_name].apply(this, arguments);
                const stacktrace = Exception.$new().getStackTrace().toString().split(',');
                _send_msg({
                    taxonomy_id: taxonomy_id,
                    description: description,
                    timestamp: timestamp,
                    class: target_class.$className,
                    method: method_name,
                    arguments: args,
                    returned_value: returned_value ? returned_value : null,
                    stacktrace: stacktrace
                });
                return returned_value;
            } catch (error) {}
        };
    });
}

export function inject_hooks(pid, process, hook_list) {
    Java.perform(() => {
        _inject_hooks(pid, process, hook_list);
    });
}

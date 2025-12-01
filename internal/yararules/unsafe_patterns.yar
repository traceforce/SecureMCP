// Unsafe system command patterns for macOS-focused detection
// These patterns detect commands that can modify critical system configurations

rule rm_rf_root {
    meta:
        id = "rm_rf_root"
        reason = "Destructive file operations"
        severity = "critical"
    strings:
        $pattern = /\brm\b.*(-r|-rf|-fr).*(\/\s|\/\*|--no-preserve-root)/
    condition:
        $pattern
}

rule csrutil_disable {
    meta:
        id = "csrutil_disable"
        reason = "System security bypass"
        severity = "critical"
    strings:
        $pattern = /\bcsrutil\s+(disable|clear)\b/
    condition:
        $pattern
}

rule nvram_modify {
    meta:
        id = "nvram_modify"
        reason = "System configuration changes"
        severity = "critical"
    strings:
        $pattern = /\bnvram\s+(set-variable|-d|-c|boot-args)/
    condition:
        $pattern
}

rule dd_device {
    meta:
        id = "dd_device"
        reason = "Destructive file operations"
        severity = "critical"
    strings:
        $pattern = /\bdd\b[^\n]*\b(of|if)=\/dev\/r?disk\d+(s\d+)?\b/
    condition:
        $pattern
}

rule curl_pipe_shell {
    meta:
        id = "curl_pipe_shell"
        reason = "Remote code execution"
        severity = "critical"
    strings:
        $pattern = /\b(curl|wget)\b[^\n]*\|\s*\b(sh|bash|zsh|tcsh)\b/
    condition:
        $pattern
}

rule process_substitution_shell {
    meta:
        id = "process_substitution_shell"
        reason = "Remote code execution"
        severity = "critical"
    strings:
        $pattern = /\b(sh|bash|zsh|tcsh)\b\s*<\s*\(\s*\b(curl|wget)\b/
    condition:
        $pattern
}

rule kext_load {
    meta:
        id = "kext_load"
        reason = "System security bypass"
        severity = "critical"
    strings:
        $pattern = /\b(kextload|kextutil)\b/
    condition:
        $pattern
}

rule spctl_disable {
    meta:
        id = "spctl_disable"
        reason = "System security bypass"
        severity = "high"
    strings:
        $pattern = /\bspctl\s+(--master-disable|--disable|--global-disable)/
    condition:
        $pattern
}

rule tccutil_reset {
    meta:
        id = "tccutil_reset"
        reason = "System security bypass"
        severity = "high"
    strings:
        $pattern = /\btccutil\s+(reset|remove)/
    condition:
        $pattern
}

rule diskutil_destructive {
    meta:
        id = "diskutil_destructive"
        reason = "Destructive file operations"
        severity = "high"
    strings:
        $pattern = /\bdiskutil\s+(erase|erasedisk|erasevolume|partition|zerodisk|randomdisk|secureerase)\b/
    condition:
        $pattern
}

rule asr_restore {
    meta:
        id = "asr_restore"
        reason = "System configuration changes"
        severity = "high"
    strings:
        $pattern = /\basr\s+(restore|imagescan)/
    condition:
        $pattern
}

rule chmod_777 {
    meta:
        id = "chmod_777"
        reason = "Insecure file permissions"
        severity = "critical"
    strings:
        $pattern = /\bchmod\b.*(777|a\+rwx|go\+w)/
    condition:
        $pattern
}

rule rm_rf {
    meta:
        id = "rm_rf"
        reason = "Destructive file operations"
        severity = "critical"
    strings:
        $pattern = /\brm\b.*(-rf|-fr|-r\s+-f|-f\s+-r)/
    condition:
        $pattern
}

rule killall {
    meta:
        id = "killall"
        reason = "Process management"
        severity = "high"
    strings:
        $pattern = /\bkillall\b/
    condition:
        $pattern
}

rule profiles_remove {
    meta:
        id = "profiles_remove"
        reason = "Service management"
        severity = "high"
    strings:
        $pattern = /\bprofiles\s+(-D|-R|remove|delete)\b/
    condition:
        $pattern
}

rule launchctl_bootout {
    meta:
        id = "launchctl_bootout"
        reason = "Service management"
        severity = "high"
    strings:
        $pattern = /\blaunchctl\s+(bootout|remove|unload)\b/
    condition:
        $pattern
}

rule shutdown_reboot {
    meta:
        id = "shutdown_reboot"
        reason = "System control"
        severity = "high"
    strings:
        $pattern = /\b(shutdown|reboot|halt)\b/
    condition:
        $pattern
}

rule tmutil_disable {
    meta:
        id = "tmutil_disable"
        reason = "System configuration changes"
        severity = "high"
    strings:
        $pattern = /\btmutil\s+(disable|disablelocal|delete)\b/
    condition:
        $pattern
}

rule installer_pkg_root {
    meta:
        id = "installer_pkg_root"
        reason = "Package installation"
        severity = "high"
    strings:
        $pattern = /\binstaller\b[^\n]*\b(-pkg|--package)\b[^\n]*\b(-target|--target)\s*\/(?:\s|$)/
    condition:
        $pattern
}

rule sudo {
    meta:
        id = "sudo"
        reason = "Privilege escalation"
        severity = "medium"
    strings:
        $pattern = /\bsudo\b/
    condition:
        $pattern
}

rule doas {
    meta:
        id = "doas"
        reason = "Privilege escalation"
        severity = "medium"
    strings:
        $pattern = /\bdoas\b/
    condition:
        $pattern
}

rule kill_force {
    meta:
        id = "kill_force"
        reason = "Process management"
        severity = "high"
    strings:
        $pattern = /\bkill\s+(-9|-kill|-sigkill)\b/
    condition:
        $pattern
}

rule launchctl_modify {
    meta:
        id = "launchctl_modify"
        reason = "Service management"
        severity = "high"
    strings:
        $pattern = /\blaunchctl\s+(stop|disable|kickstart|bootstrap)\b/
    condition:
        $pattern
}

rule chown_recursive {
    meta:
        id = "chown_recursive"
        reason = "File ownership changes"
        severity = "medium"
    strings:
        $pattern = /\bchown\s+(-R|-r)\b/
    condition:
        $pattern
}

rule osascript {
    meta:
        id = "osascript"
        reason = "System automation"
        severity = "medium"
    strings:
        $pattern = /\bosascript\b/
    condition:
        $pattern
}

rule shell_exec {
    meta:
        id = "shell_exec"
        reason = "Code execution"
        severity = "medium"
    strings:
        $pattern = /\b(bash|sh|zsh|tcsh)\s+-c\b/
    condition:
        $pattern
}

rule python_exec {
    meta:
        id = "python_exec"
        reason = "Code execution"
        severity = "medium"
    strings:
        $pattern = /\bpython3?\s+(-c|-m\s+code)/
    condition:
        $pattern
}

rule defaults_write {
    meta:
        id = "defaults_write"
        reason = "System configuration changes"
        severity = "high"
    strings:
        $pattern = /\bdefaults\s+write\b/
    condition:
        $pattern
}

rule pmset {
    meta:
        id = "pmset"
        reason = "System configuration changes"
        severity = "high"
    strings:
        $pattern = /\bpmset\b/
    condition:
        $pattern
}

rule networksetup {
    meta:
        id = "networksetup"
        reason = "System configuration changes"
        severity = "high"
    strings:
        $pattern = /\bnetworksetup\b/
    condition:
        $pattern
}

rule scutil {
    meta:
        id = "scutil"
        reason = "System configuration changes"
        severity = "high"
    strings:
        $pattern = /\bscutil\b/
    condition:
        $pattern
}

rule brew_install {
    meta:
        id = "brew_install"
        reason = "Package installation"
        severity = "low"
    strings:
        $pattern = /\bbrew\s+(install|upgrade|tap)\b/
    condition:
        $pattern
}

rule npm_global {
    meta:
        id = "npm_global"
        reason = "Package installation"
        severity = "low"
    strings:
        $pattern = /\bnpm\s+i(nstall)?\s+(-g|--global)\b/
    condition:
        $pattern
}

rule pip_install {
    meta:
        id = "pip_install"
        reason = "Package installation"
        severity = "low"
    strings:
        $pattern = /\bpip3?\s+install\b/
    condition:
        $pattern
}

rule gem_install {
    meta:
        id = "gem_install"
        reason = "Package installation"
        severity = "low"
    strings:
        $pattern = /\bgem\s+install\b/
    condition:
        $pattern
}

rule cargo_install {
    meta:
        id = "cargo_install"
        reason = "Package installation"
        severity = "low"
    strings:
        $pattern = /\bcargo\s+install\b/
    condition:
        $pattern
}

rule port_install {
    meta:
        id = "port_install"
        reason = "Package installation"
        severity = "low"
    strings:
        $pattern = /\bport\s+install\b/
    condition:
        $pattern
}

rule python_eval {
    meta:
        id = "python_eval"
        reason = "Code execution"
        severity = "critical"
    strings:
        $pattern = /\beval\s*\(/
    condition:
        $pattern
}

rule python_exec_func {
    meta:
        id = "python_exec_func"
        reason = "Code execution"
        severity = "critical"
    strings:
        $pattern = /\bexec\s*\(/
    condition:
        $pattern
}

rule python_pickle_loads {
    meta:
        id = "python_pickle_loads"
        reason = "Code execution"
        severity = "critical"
    strings:
        $pattern = /\bpickle\.(loads?|Unpickler)\s*\(/
    condition:
        $pattern
}

rule python_subprocess_shell {
    meta:
        id = "python_subprocess_shell"
        reason = "Remote code execution"
        severity = "high"
    strings:
        $pattern = /\bsubprocess\.(Popen|call|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True/
    condition:
        $pattern
}

rule python_os_system {
    meta:
        id = "python_os_system"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\bos\.system\s*\(/
    condition:
        $pattern
}

rule python_compile {
    meta:
        id = "python_compile"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\bcompile\s*\([^)]*,\s*['"]/
    condition:
        $pattern
}

rule python_marshal_loads {
    meta:
        id = "python_marshal_loads"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\bmarshal\.loads?\s*\(/
    condition:
        $pattern
}

rule python_yaml_load {
    meta:
        id = "python_yaml_load"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\byaml\.(load|unsafe_load|FullLoader)\s*\(/
    condition:
        $pattern
}

rule python_sql_injection {
    meta:
        id = "python_sql_injection"
        reason = "Remote code execution"
        severity = "high"
    strings:
        $pattern = /\b(execute|executemany)\s*\([^)]*[%+]/
    condition:
        $pattern
}

rule python_deserialize {
    meta:
        id = "python_deserialize"
        reason = "Code execution"
        severity = "medium"
    strings:
        $pattern = /\b(__import__|getattr|setattr|delattr)\s*\([^)]*['"]/
    condition:
        $pattern
}

rule nodejs_eval {
    meta:
        id = "nodejs_eval"
        reason = "Code execution"
        severity = "critical"
    strings:
        $pattern = /\beval\s*\(/
    condition:
        $pattern
}

rule nodejs_function_constructor {
    meta:
        id = "nodejs_function_constructor"
        reason = "Code execution"
        severity = "critical"
    strings:
        $pattern = /\bnew\s+Function\s*\(/
    condition:
        $pattern
}

rule nodejs_child_process_exec {
    meta:
        id = "nodejs_child_process_exec"
        reason = "Remote code execution"
        severity = "high"
    strings:
        $pattern = /\bchild_process\.(exec|execSync|spawn|spawnSync)\s*\(/
    condition:
        $pattern
}

rule nodejs_settimeout_string {
    meta:
        id = "nodejs_settimeout_string"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\b(setTimeout|setInterval)\s*\([^,)]*['"]/
    condition:
        $pattern
}

rule nodejs_require_dynamic {
    meta:
        id = "nodejs_require_dynamic"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\brequire\s*\(\s*[^'"][^)]*\)/
    condition:
        $pattern
}

rule nodejs_fs_writefile {
    meta:
        id = "nodejs_fs_writefile"
        reason = "Destructive file operations"
        severity = "medium"
    strings:
        $pattern = /\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync)\s*\(/
    condition:
        $pattern
}

rule nodejs_serialize_eval {
    meta:
        id = "nodejs_serialize_eval"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\b(eval|Function)\s*\([^)]*JSON\.(parse|stringify)/
    condition:
        $pattern
}

rule nodejs_vm_runincontext {
    meta:
        id = "nodejs_vm_runincontext"
        reason = "Code execution"
        severity = "high"
    strings:
        $pattern = /\bvm\.(runInContext|runInNewContext|runInThisContext)\s*\(/
    condition:
        $pattern
}

rule nodejs_express_eval {
    meta:
        id = "nodejs_express_eval"
        reason = "Remote code execution"
        severity = "critical"
    strings:
        $pattern = /\bexpress\s*\([^)]*\)[^}]*eval\s*\(/
    condition:
        $pattern
}

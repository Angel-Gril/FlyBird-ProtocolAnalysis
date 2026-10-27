set pagination off
set confirm off
set height 0
set width 0

# 地址来自 src/pclntab.py 对目标二进制的解析结果（x86_64 构建，ET_EXEC 非 PIE）
# 换版本/换架构必须重新解析，否则断点地址无效。
#
#   key32     0x77e8a0
#   OpenAPXS  0x77e980
#   RouterCfg 0x779240

# key32(s string) -> []byte     Go ABI: RAX=ptr, RBX=len
break *0x77e8a0
commands
silent
printf "\n### key32 entry rax=%p rbx=%lu\n", $rax, $rbx
x/44cb $rax
continue
end

# OpenAPXS(body []byte, aes []byte, sign []byte, ids)
break *0x77e980
commands
silent
printf "\n### OpenAPXS entry\n"
printf "body=%p len=%lu cap=%lu ids=%#lx\n", $rax, $rbx, $rcx, $rdx
printf "aes=%p len=%lu  sign=%p len=%lu\n", $rdi, $rsi, $r9, $r10
x/4gx $rax
x/4gx $rdi
x/4gx $r9
if $rbx > 0 && $rbx < 1000000
  dump binary memory /tmp/apex_body.bin $rax ($rax + $rbx)
  printf "body dumped: %lu bytes\n", $rbx
end
set $retaddr = *(unsigned long*)$rsp
printf "return address = %p\n", $retaddr
tbreak *$retaddr
commands
silent
printf "\n### OpenAPXS return rax=%p rbx=%lu\n", $rax, $rbx
if $rbx > 0 && $rbx < 1000000
  dump binary memory /tmp/apex_plain.bin $rax ($rax + $rbx)
  printf "plaintext dumped: %lu bytes\n", $rbx
end
continue
end
continue
end

# RouterConfig —— 打包身份（identities）的来源，确认是否被调用
break *0x779240
commands
silent
printf "\n### RouterConfig entry a=%p b=%lu c=%lu d=%p\n", $rax, $rbx, $rcx, $rdx
bt 4
continue
end

continue

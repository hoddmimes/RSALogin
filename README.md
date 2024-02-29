# RSALogin 



This project contain and provides functionality for using generate (RSA) **SSH keys** to authorize an arbitrary 'client/server' connection.

SSH generated keys are used when establish encrypted sessions with the SSH server using the SSH utility.

In case you would like to use generate SSH keys to authorize your own arbitrary service in the same way as
a SSH server does this utility can certainly help you. 

What you typically wil do is to provide SSH generated keys using a standard SSH utility e.g
see [ssh-keygen](https://www.ssh.com/academy/ssh/keygen).

The steps taking to establish an authorized session between a 'client' and a server using the SSH keys are the following.

* A *__client__* is assumed to be in a posetion of a private SSH key.
* A *__server__* is assumed to be in postion of the _client_ public SSH key. Typicaly the client will upload its public SSH key file to the server.

* The **SSHKeyAuthorization** object frame the functionality needed for establish an authorized session. Both the _client_ and _server_ app will create an instance of SSHKeyAuthorization.

 
1. As a first step the client a server will establish a common secure key (256 bit) using the SSH public key data and the [Diffe-Hellman key exchange protocol](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
2. When having a common secure key the client and server needs to establish a secure communication channel. Chose your favourite transport and encryption.
3. When having a secure communication the server will generate a challege (random 128 bytes) being encrypted with the SSH public key. The encrypted challange is sent to the client over the secure channel of choice.
4. The client can only decrypt the challange if it has the SSH private key. When the client has decrypt the challange, the client will send back the challange (decrypted) over the secure channel to the client.
5. The client will verify the challange from the server with the one generated to the client. If being the same the server will known that the client has the private SSH key.


The [Test.java](https://github.com/hoddmimes/RSALogin/blob/main/src/main/java/com/hoddmimes/sshauth/Test.java) program schematically implements and test the steps above using the **SSHKeyAuthorization** object. 

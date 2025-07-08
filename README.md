Passi per utilizzare il servizio di snapshot

Effettuare il make di kernel_module, control_snap e restore_snap

Per montare il modulo kernel entrare nella directory kernel_module e eseguire
sudo insmod snapshot.ko 

Per attivare/disattivare il servizio di snapshot entrare nella directory control_snap e lanciare 
sudo ./control_snap activate dev/loopX 12345
sudo ./control_snap deactivate dev/loopX 12345
(/dev/loopX è il nome da dare al device con X che indica un numero arbitrario, 12345 è la password richiesta)

All'interno della directory SINGLE-FILEFS: 
per montare il modulo --> sudo insmod singlefilefs.ko
per collegare l'immagine al device --> sudo losetup /dev/loopX image
per inizializzare il filesystem --> sudo ./singlefilemakefs /dev/loopX
per montare il device --> sudo mount -t singlefilefs /dev/loopX mount

per modificare il contenuto del device entrare in SINGLE-FILEFS/user e lanciare
./user ../mount/the-file "xxxxxxxxxxx" 0 
("xxxxxxxxxx" indica una qualsiasi stringa)

Per ripristinare lo snapshot sul device:
smontare il device
entrare nella directory restore_snap ed eseguire sudo ./restore_snap /dev/loopX

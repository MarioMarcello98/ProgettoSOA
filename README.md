# Passi per utilizzare il servizio di snapshot

Effettuare il `make` di `kernel_module`, `control_snap` e `restore_snap`.

---

Per montare il modulo kernel entrare nella directory `kernel_module` e eseguire:

```bash
sudo insmod snapshot.ko
```

---

Per attivare/disattivare il servizio di snapshot entrare nella directory `control_snap` e lanciare:

```bash
sudo ./control_snap activate /dev/loopX 12345
sudo ./control_snap deactivate /dev/loopX 12345
```

`/dev/loopX` è il nome da dare al device (X indica un numero arbitrario), `12345` è la password richiesta.

---

All'interno della directory `SINGLE-FILEFS`:

- per montare il modulo:  
  ```bash
  sudo insmod singlefilefs.ko
  ```

- per collegare l'immagine al device:  
  ```bash
  sudo losetup /dev/loopX image
  ```

- per inizializzare il filesystem:  
  ```bash
  sudo ./singlefilemakefs /dev/loopX
  ```

- per montare il device:  
  ```bash
  sudo mount -t singlefilefs /dev/loopX mount
  ```

---

Per modificare il contenuto del device entrare in `SINGLE-FILEFS/user` e lanciare:

```bash
./user ../mount/the-file "quello che vuoi" 0
```

---

Per ripristinare lo snapshot sul device:

1. Smontare il device.
2. Entrare nella directory `restore_snap` ed eseguire:

   ```bash
   sudo ./restore_snap /dev/loopX
   ```

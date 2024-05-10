#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>


// /mnt/d/Obiecte_Uni/SO/labs/proiect/test


// structura cu informatiile despre fiecare fisier
typedef struct meta_data{
    char nume[300];
    long id;
    long long size;

    char time_modif[300];
    char path_to_file[300];
    char situation[30];
}meta_data_t;

//structura generala utiliata pentru functii
typedef struct dir_data{

    meta_data_t list[300];
    char name_dir[300];
    long id_dir;
    int moved_file;
    int counter;
}dir_data_t;

typedef struct total{
    dir_data_t list_dir[11];
    int id_counter;
    char output[300];
    char safe_location[300];
}total_t;

//functie de afisare a datelor
void show_data(dir_data_t elem){
    for(int i = 0;i<elem.counter;i++){
        printf("Data from %s:\n",elem.list[i].nume);
        printf("ID:%ld\n",elem.list[i].id);
        printf("Size:%lld\n",elem.list[i].size);
        printf("Situation:%s\n",elem.list[i].situation);
        printf("Path:%s\n",elem.list[i].path_to_file);
        printf("LastTimeModif:%s\n",elem.list[i].time_modif);
        printf("\n");
    }
}

//functie de comparare a datelor intr valorile din fisier si cele actuale
dir_data_t *compar(dir_data_t *elem,dir_data_t actual){

    for(int i=0;i<elem->counter;i++){
        for(int j=0;j<actual.counter;j++){

            if(elem->list[i].id == actual.list[j].id){

                if(strcmp(elem->list[i].nume,actual.list[j].nume) != 0){
                
                    strcpy(elem->list[i].situation,"renamed");  //cazul in care e schimbat numele
                    
                }
                else if(strcmp(elem->list[i].path_to_file,actual.list[j].path_to_file) != 0){
                    
                    strcpy(elem->list[i].situation,"moved");    //cazul in care sa mutat in alt director
                    
                }
                else if(strcmp(elem->list[i].time_modif,actual.list[j].time_modif) != 0){
                    
                    strcpy(elem->list[i].situation,"modified"); //cazul in care sa modificat ceva in fisier
                    
                }
                else{

                    strcpy(elem->list[i].situation,"old");  // fara modificare
                }
            }
            if((j == actual.counter) && (elem->list[i].id != actual.list[j].id)){
                strcpy(elem->list[i].situation,"new");  // fiser nou
                
            }
        
            

        }
    }
    return elem;
}


//functie care verifica daca sa schimbat ceva in fisier zice ce sa schimbat si adauga iar snapshotu now
void compar_data_and_change(dir_data_t *elem,char *output,char *name){
    dir_data_t actual_list;
    actual_list.counter=0;
    meta_data_t tmp;

    char path[1024];

    snprintf(path, sizeof(path), "%s/%s",output,name);

    int fd = open(path, O_RDONLY);

    if(fd == -1){
        printf("Eroare citire fisier(compar_data_and_change)\n");
        exit(EXIT_FAILURE);
    }

    ssize_t bytes_read;

    for(int i=0;i<elem->counter;i++){
        //citeste cite o structur meta_data_d
        bytes_read = read(fd, &tmp, sizeof(meta_data_t));
        //verifica ca citirea sa efectuat corect
        if (bytes_read == -1) {
            perror("Eroare la citire din fisier(compar_data_and_change)");
            close(fd);
            exit(EXIT_FAILURE);
        }

        actual_list.list[actual_list.counter] = tmp;
        actual_list.counter++;
    }

    close(fd);

    elem = compar(elem,actual_list);
}



//functie care adauga datele dupa ce a fost cercetat fiecare fisier
//din directoru dat
int add_to_file(dir_data_t *elem,char *output,char *name){

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", output, name);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        printf("Eroare deschidere fisier (add_to_file)\n");
        exit(EXIT_FAILURE);
    }


    ssize_t bytes_written; 
    bytes_written = write(fd, elem, sizeof(dir_data_t));
    if (bytes_written == -1) {
        perror("Eroare la scriere in fisier(add_to_file)");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}


//functie care schimba locatia la fisier daca e sigur 
//locatia e directoru izolated_space_dir cu path-ul din fisieru specificat
void move_file_in_safe_location(char *file_path,char *safe_location){

    if(rename(file_path, safe_location) == 0){
        // printf("Fisier mutat cu succes.\n");
    }else{
        printf("Eroare la mutarea fisierului(move_file_in_safe_location)\n");
        exit(EXIT_FAILURE);
    }
}


//functie care verifica daca un fisier are drepturi si
//returneaza 0 daca nu are nici un drept indicand ca e corupt

void verif_drepturi_lipsa(struct stat sb,char *name_of_file,char *returned_word){

    char word[40] = "SAFE"; //cuvant daca totu e ok
    char line[500]; 
    int result;
    char buffer[250]; //infomratia care vine din script
    char *script = "/mnt/d/obiecte_uni/SO/labs/proiect/verify_for_malicious.sh"; // path-ul unde e scriptu
    // creaza linia care va fi furnizata la script prin pipe    
    snprintf(line, sizeof(line), "%s %s", script, name_of_file);

    // printf("%s\n",line);
    // printf("Permisiuni: %o\n",(sb.st_mode & 0777));

    //se verifica drepturile care le are fisieru
    if((sb.st_mode & 0777 ) == 0555){
        
        FILE* pipe = popen(line, "r");

        //verifica daca sa deschis fisieru
        if(!pipe){
            printf("Eroare la deschiderea pipe-ului(verif_drepturi_lipsa)\n");
            exit(EXIT_FAILURE);
        }
        //citeste informatia care e primita de la echo in buffer care e printata mai apoi
        while(fgets(buffer, sizeof(buffer), pipe) != NULL){
            // printf("%s", buffer); // Afișează rezultatele întoarse de script
        }

        result = pclose(pipe);

        //verifica daca sa inchis corect
        if(result == -1){
            printf("Eroare la așteptarea închiderii pipe-ului(verif_drepturi_lipsa)\n");
            exit(EXIT_FAILURE);
        }

        //verifica sa fie rezultatul care trebuie /0 daca nu e ce trebuie /oricare numar in dependenta de ce e in scrpit
        if (!WIFEXITED(result)){
            printf("Procesul nu s-a încheiat normal.\n");
            exit(EXIT_FAILURE);
        }

    }else{
        strcpy(returned_word,word);
        return;
    }


    strcpy(returned_word,buffer);
}




//functie care creaza fisieru cu date daca nu a mai fost creat
//si adauga informatiile despre celelalte fisiere
//sau trimite datele mai departe sa fie verificate
void info_from_dir(char *main_name,char *name,dir_data_t *elem,char *safe_location){


    pid_t pid;
    int pfd[2]; 
    
    
    //pt functiile write si read la pipe
    int len = 0; // lungime care va fi pusa in write sau read cu buff
    char returned_word[250]; // cuvantul obtinut de la verif_drepturi_lipsa

    char keyword[50] = "SAFE";

    DIR *dir;
    struct dirent *elem_dir;
    struct stat sb;
    char path[1024];
    char safe_location_with_filename[1024];

    


    if((dir = opendir(name)) == NULL){
        printf("\nNu se deschide directoru(info_from_dir) %s\n",name);
        exit(EXIT_FAILURE);
    }else{

       
        while((elem_dir = readdir(dir)) != NULL){
            
            if (strcmp(elem_dir->d_name, ".") == 0 || strcmp(elem_dir->d_name, "..") == 0) {
                continue;
            }

            //creaza path-ul de unde tre sa se citeasca datele despre fisier
            snprintf(path, sizeof(path), "%s/%s",name, elem_dir->d_name);


            if(elem_dir->d_type == DT_DIR){
                info_from_dir(main_name,path,elem,safe_location);
            }


            //verifica daca lstat functioneaza cum trebuie
            if (lstat(path, &sb) == -1) {
                printf("Eroare la primirea datelor despre fisier %s: %s\n", path, strerror(errno));
                exit(EXIT_FAILURE);
            }

            
            if(pipe(pfd)<0){
                perror("Eroare la crearea pipe-ului\n");
                exit(EXIT_FAILURE);
            }

            if((pid = fork()) < 0){
                printf("Eroare fork() (info_from_dir)\n");
                exit(EXIT_FAILURE);
            }
            if(pid == 0){ //child

                close(pfd[0]);

                verif_drepturi_lipsa(sb,path,returned_word);

                len = strlen(returned_word)+1;
                
                write(pfd[1],returned_word,len);
                
                close(pfd[1]);

                closedir(dir);
                
                exit(0);

            }else{  //parent

                char buff[256];
                close(pfd[1]);
                
                read(pfd[0],buff,255);
                
                if(strcmp(keyword,buff) == 0){
                    

                    strcpy(elem->list[elem->counter].path_to_file,path);
                    strcpy(elem->list[elem->counter].nume,elem_dir->d_name);
                    elem->list[elem->counter].id = sb.st_ino;
                    elem->list[elem->counter].size = sb.st_size;
                    strcpy(elem->list[elem->counter].time_modif,ctime(&sb.st_mtime));
                    
                    elem->counter++;

                }else{

                    snprintf(safe_location_with_filename, sizeof(safe_location_with_filename), "%s/%s",safe_location, elem_dir->d_name);
                    move_file_in_safe_location(path,safe_location_with_filename);

                    elem->moved_file++;
                    
                }

                close(pfd[0]);
            }
            
        }
        
        
    }

    closedir(dir);
    return;
}



//functie pentru citire director si verificare daca exista fisieru cu date
int check_for_filedata(char *name,char *output){
    DIR *dir;
    struct dirent *elem_dir;

    if((dir = opendir(output)) == NULL){
        printf("\nNu se deschide directoru (check_for_filedata)\n");
        exit(EXIT_FAILURE);
    }else{

        //parcurge directoru
        while((elem_dir = readdir(dir)) != NULL){
            //se opreste daca gaseste fisieru si returneaza 1

            if(strcmp(name,elem_dir->d_name) == 0){
                closedir(dir);
                return 1;
            }
        }
    }
    closedir(dir);
    return 0;
}


//verifica directoru pentru ambele cazuri: 
//1.Cind nu a mai fost inregistrate pina acum datele despre el
//2.Cind exista snapshot si se certceteaza datele daca sunt la fel
void verif_dir(char *name,total_t *elem){
    
    elem->list_dir[elem->id_counter].counter = 0;
    elem->list_dir[elem->id_counter].moved_file = 0;


    //verifica daca exista snapshot cu directoru in output return 0 daca nu return 1 daca da
    int check = check_for_filedata(elem->list_dir[elem->id_counter].name_dir,elem->output);


    //obtine informatiile din directorul dat
    info_from_dir(name,name,&(elem->list_dir[elem->id_counter]),elem->safe_location);


    if(check == 0){
        for(int i =0;i<elem->list_dir[elem->id_counter].counter;i++){
            
            //initializeaza cu new toate fisierele daca nu exista snapshot cu acest director
            strcpy(elem->list_dir[elem->id_counter].list[i].situation,"new");
            
        }
    }
    
    if(check == 1){
        //compara directoru cu snapshotu asociat lui
        compar_data_and_change(&(elem->list_dir[elem->id_counter]),elem->output,elem->list_dir[elem->id_counter].name_dir);
        
    }
    
    // printf("\n------------------------------------------------------------------------------\n");
    // show_data(elem->list_dir[elem->id_counter]);
    // printf("\n------------------------------------------------------------------------------\n");

    //adauga datele noi sau modificari daca sau intimplat
    add_to_file(&(elem->list_dir[elem->id_counter]),elem->output,elem->list_dir[elem->id_counter].name_dir);


    printf("Snapshot %s for directory crated successfully\n",elem->list_dir[elem->id_counter].name_dir);

}


//------------------------------------------------------------------------------------------------------------------------------------------



//functie pentru salvarea numelui directorului care vine ca argv
void save_name_dir(char *path,total_t *elem){

    char *lastSlash = strrchr(path, '/');
    //obtine doar ultimul cuvint dupa ultima /
    if (lastSlash != NULL) {
        strcpy(elem->list_dir[elem->id_counter].name_dir, lastSlash + 1);
    }else{
        strcpy(elem->list_dir[elem->id_counter].name_dir, path);
    }
    //adauga la final .bin
    strcat(elem->list_dir[elem->id_counter].name_dir,".bin");

}


//functie care salveaza datele daca e director
void save_argv_data(char *path,total_t *elem){
    save_name_dir(path,elem);   //pt salvare nume la dir

    struct stat sb;
    lstat(path,&sb);
    elem->list_dir[elem->id_counter].id_dir = sb.st_ino;  //pt salvare id la dir

}


//functie care verifica fiecare argument daca e director
int check_argv(char *path){

    struct stat sb;
    lstat(path,&sb);
    
    return S_ISDIR(sb.st_mode);
}


//------------------------------------------------------------------------------------------------------------------------------------------

void function_for_fork(int argc,char **argv){

    pid_t pid;
    int pfd[2];
    int status;

    total_t elem;
    elem.id_counter = 0;

    pid_t pid_list[argc];
    int moved_files[argc];
    // int counter=0;

    for(int i=1;i<argc;i++){
        //conditia care salveza path-ul la directoru unde va fi salvat metadata despre directoare
        if(strcmp(argv[i],"-o")==0){
            strcpy(elem.output,argv[i+1]);
            i=i+2;        
        }
        //conditia care salveaza path-ul la directoru unde vor fi trimise fisierele corupte
        if(strcmp(argv[i],"-s")==0){
            strcpy(elem.safe_location,argv[i+1]);
            i=i+2;        
        }

        int check = check_argv(argv[i]);  

        
        if(check != 0){
            

            if(pipe(pfd)<0){
                perror("Eroare la crearea pipe-ului\n");
                exit(EXIT_FAILURE);
            }

            if((pid = fork()) < 0){
                printf("Eroare fork() (function_for_fork)\n");
                exit(EXIT_FAILURE);
            }
            if(pid == 0){  // child

                close(pfd[0]);

                save_argv_data(argv[i],&elem);
                verif_dir(argv[i],&elem);

                write(pfd[1],&elem.list_dir[elem.id_counter].moved_file,sizeof(elem.list_dir[elem.id_counter].moved_file));
                
                close(pfd[1]);
                exit(0);
            }
            else{ // parent

                close(pfd[1]);

                read(pfd[0],&moved_files[elem.id_counter],sizeof(int));

                if(i == argc-1){
                    
                    pid_list[elem.id_counter] = waitpid(pid,&status,0);

                    for(int j = 0;j<=elem.id_counter;j++){
                        printf("Procesul copil %d s-a incheiat cu PID-ul %d si cu %d fisiere potential periculoase\n",j+1,pid_list[j],moved_files[j]);
                    }

                }else{
                    pid_list[elem.id_counter] = waitpid(pid,&status,0);

                }

                elem.id_counter++;

                close(pfd[0]);
            }
        }

    }
    

    
}




//------------------------------------------------------------------------------------------------------------------------------------------
//Pt direcotru unde va fi salvat metadata are in fata -o director
//Pt directoru unde vor fi trimise fisierele corupte are forma -s director
//Pt celelalte directoare doar li se da path-ul ignorand argumentele care nu sunt directoare
int main(int argc, char **argv){
    if(argc > 10){
        printf("\nPrea multe argumente\n");
        exit(EXIT_FAILURE);
    }
    else{
       function_for_fork(argc,argv);
    }

    return 0;
}


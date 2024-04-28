#include <stdio.h>
#include "str2dfa.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


// Function to write a list of strings to a file line by line
void write_strings_to_file(const char *filename, char **strings, int num_strings) {
    // Open the file for writing
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file for writing.\n");
        return;
    }

	printf("Patterns:\n");

    // Write each string to the file line by line
    for (int i = 0; i < num_strings; i++) {
		printf("%s\n", strings[i]);
        fprintf(file, "%s\n", strings[i]);
    }

    // Close the file
    fclose(file);
}

int get_num_lines(const char *filename){
	FILE *file = fopen("pats.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return 1;
    }

	int n_entry = 0;
    char buffer[64];
    while (fgets(buffer, 64, file)) {
        n_entry++;
    }
	fclose(file);
	return n_entry;
}

// essa função recebe o automato recém alocado e o arquivo que representa o autômato. Inicia os campos entries e entry_number do dfa
int str2dfa(struct fast_p* fast_patterns_array, size_t p_len, struct dfa_struct *result) {

    char* fps[p_len];
	for(int i = 0; i < p_len; i++){
		fps[i] = fast_patterns_array[i].fp;
	}

	// escreve os fast pattern linha a linha no arquivo data.txt
	write_strings_to_file("data.txt", fps, p_len);

	// chama python script para criar o automato
	system("python3 str2dfa.py data.txt > pats.txt");

	int n_entry = get_num_lines("pats.txt");

	// preenche a struct dfa_struct
	// Open the file
    FILE *file = fopen("pats.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return 1;
    }

	struct dfa_entry *entries = (struct dfa_entry *)malloc(sizeof(struct dfa_entry) * n_entry);
	char line[1024];
	int i = 0, j;

	int key_s, value_s, value_f;
	char key_unit;
    char padrao[256];

    while (fgets(line, sizeof(line), file)) {
        // Parse the line
        sscanf(line, "%d,%c,%d,%d,%s", &key_s, &key_unit, 
				&value_s, &value_f, padrao);

		entries[i].key_state = (uint16_t)key_s;
		entries[i].key_unit = (uint8_t)key_unit;
		entries[i].value_state = (uint16_t)value_s;
		entries[i].value_flag = (uint16_t)value_f;

        if(strcmp(padrao, "~") != 0){
            for(j = 0; j < p_len; j++){
                if(strcmp(padrao, fast_patterns_array[j].fp) == 0){
                    entries[i].fp__rule_index = j;  // coloca o índice do vetor de regras para este port group
                }
            }
        }
        else{
            entries[i].fp__rule_index = -1;  // significa que não é um estado final
        }

        i++;
    }
	result->entry_number = n_entry;
	result->entries = entries;
    // Close the file
    fclose(file);			
	return 0;
}

// essa função recebe o automato recém alocado e o arquivo que representa o autômato. Inicia os campos entries e entry_number do dfa
int str2dfa__to_contents(char** contents_array, size_t p_len, struct dfa_struct *result) {

	// escreve os fast pattern linha a linha no arquivo data.txt
	write_strings_to_file("data.txt", contents_array, p_len);

	// chama python script para criar o automato
	system("python3 str2dfa.py data.txt > pats.txt");

	int n_entry = get_num_lines("pats.txt");

	// preenche a struct dfa_struct
	// Open the file
    FILE *file = fopen("pats.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file.\n");
        return 1;
    }

	struct dfa_entry *entries = (struct dfa_entry *)malloc(sizeof(struct dfa_entry) * n_entry);
	char line[1024];
	int i = 0, j;

	int key_s, value_s, value_f;
	char key_unit;
    char padrao[256];

    while (fgets(line, sizeof(line), file)) {
        // Parse the line
        sscanf(line, "%d,%c,%d,%d,%s", &key_s, &key_unit, 
				&value_s, &value_f, padrao);

		entries[i].key_state = (uint16_t)key_s;
		entries[i].key_unit = (uint8_t)key_unit;
		entries[i].value_state = (uint16_t)value_s;
		entries[i].value_flag = (uint16_t)value_f;

        entries[i].fp__rule_index = -1;  // significa que não é um estado final
        i++;
    }
	result->entry_number = n_entry;
	result->entries = entries;
    // Close the file
    fclose(file);			
	return 0;
}

#include <stdio.h>
#include <stdlib.h>

// Function to write a list of strings to a file line by line
void write_strings_to_file(const char *filename, const char *strings[], int num_strings) {
    // Open the file for writing
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file for writing.\n");
        return;
    }

    // Write each string to the file line by line
    for (int i = 0; i < num_strings; i++) {
        fprintf(file, "%s\n", strings[i]);
    }

    // Close the file
    fclose(file);
}

int main() {
    // Example list of strings
    const char *strings[] = {"Hello", "World", "This", "is", "a", "test"};

    // Write the strings to a file
    write_strings_to_file("data.txt", strings, sizeof(strings) / sizeof(strings[0]));
    system("python3 str2dfa.py > pats.txt");

    return 0;
}

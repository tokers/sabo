#include <bits/stdc++.h>
using namespace std;

int main(int argc, char *argv[]) {

    if (argc != 4) {
        exit(127);
    }

    FILE *dataout = fopen(argv[2], "r");
    FILE *userout = fopen(argv[3], "r");
    int a, b, c,d;
    int sizestd = fseek(dataout, 0, SEEK_SET);
    int sizeuser = fseek(userout, 0, SEEK_SET);
    while (~fscanf(dataout, "%d %d", &a, &b)) {
        int res = fscanf(userout, "%d %d", &c, &d);
        if (res == EOF) {
            exit(4); // WA
        }
        if (a + b != c + d) {
            exit(4); // WA
        } 
    }
    if (sizestd != sizeuser) {
        exit(1); // PE
    } else {
        exit(0); // AC
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#include "app.h"

/* Application entry */
int main( int argc, char *argv[] )
{
	(void)(argc);
	(void)(argv);

	// Use current time as seed for initializing the random generator
	srand( (unsigned int) time(NULL) );

	// Get the previously generated random prime from file
	int old_prime = 0;
	int ret = load_prime( &old_prime, sizeof( int ) );
	if (ret != 0) {
		printf("Warning: Could not retrieve old prime from file.\n");
	} else {
		printf("Successfully retrieved the old prime (%d) from file.\n", old_prime);
	}

	// Generate the new random prime
	int p, new_prime;
	do {
		// Generate a random prime
		p = 0;
		do {
			new_prime = get_random_int();
			p = is_prime( new_prime );
		} while( p != 1 );

	} while( new_prime == old_prime );

	// Store the newly generated random prime on file
	ret = save_prime( &new_prime, sizeof( int) );
	if (ret != 0) {
		printf("Error: Could not save new prime to file.\n");
	} else {
		printf("Successfully saved the new prime (%d) to file.\n", new_prime);
	}

	return 0;
}

int get_random_int( void ) {
	return rand();
}

int is_prime( int n ) {

	int p = 1;

	if ( n <= 1 ) {
		p = 0;
	} else if ( n != 2 && (n % 2) == 0) {
		p = 0;
	} else {
		for ( int i = 2; i <= sqrt(n); ++i ) {
	 		// If n is divisible by any number between 2 and n/2, it is not prime
			if ( n % i == 0 ) {
				p = 0;
				break;
			}
		}
	}

    return p;
}

int load_prime( int* prime, const size_t prime_size ) {

	FILE *fp = fopen( PRIME_FILENAME, "r" );
	if ( fp == NULL ){
		return 1;
	}
	fread( prime, prime_size, 1, fp );
	fclose( fp );
	return 0;
}

int save_prime( const int* prime, const size_t prime_size ) {

	FILE *fp = fopen( PRIME_FILENAME, "w");
	if ( fp == NULL ){
		return 1;
	}
	fwrite( prime, prime_size, 1, fp);
	fclose( fp );
	return 0;
}

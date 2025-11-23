#ifndef _APP_H_
#define _APP_H_

#define PRIME_FILENAME "prime.txt"

int get_random_int( void );
int is_prime( int n );
int load_prime( int* prime, const size_t prime_size );
int save_prime( const int* prime, const size_t prime_size );


#endif /* !_APP_H_ */

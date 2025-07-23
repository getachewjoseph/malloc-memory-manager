#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#include "myMalloc.h"

#define MALLOC_COLOR "MALLOC_DEBUG_COLOR"

static bool check_env;
static bool use_color;

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();

static bool isMallocInitialized;

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}

/**
 * @brief Helper function to get the header to the left of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencepost)
 */
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);

  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation
  (void) raw_size;

  if (raw_size == 0) {
    return NULL;
  }

  int check = 0;

  size_t remainder = raw_size % 8;
  size_t allocable_size = 0;
  // (get_size(current) - alloc_header_size) - 1
  if (remainder != 0) {
    allocable_size = (8 - remainder) + raw_size;
  }
  else {
    allocable_size = raw_size;
  }

  if (allocable_size == 8) {
    allocable_size = 16;
  }

  size_t real_size = allocable_size + ALLOC_HEADER_SIZE;
  size_t index = (allocable_size / 8) - 1;

  if (index > N_LISTS - 1) {
    index = N_LISTS - 1;
  }

  header * sentinel = &freelistSentinels[index];

  header * current = sentinel->next;

  size_t curr_size = 0;

  while (1) {
    if (index == (N_LISTS - 1)) {
      curr_size = get_size(current);
      while (curr_size < real_size) {
        current = current->next;
        curr_size = get_size(current);

        if (current == sentinel) {
          check = 1;
          break;
        }
      }

      if (check != 1) {
        if (curr_size == real_size) {
          // use the full block that is used
          set_state(current, ALLOCATED);
          current->prev->next = current->next;
          current->next->prev = current->prev;
          return (header *) current->data;
        }
        else if (curr_size - real_size < sizeof(header)) {
          // cant split use the full block
          set_state(current, ALLOCATED);
          current->prev->next = current->next;
          current->next->prev = current->prev;
          return (header *) current->data;
        }
        else if (curr_size - real_size >= N_LISTS * 8) {
          // stay in n lists
          size_t new_size = curr_size - real_size;
          set_size(current, new_size);

          header *new_block = (header *)((char *)current + new_size);
          set_state(new_block, ALLOCATED);

          new_block->left_size = new_size;
          set_size(new_block, real_size);
          get_right_header(new_block)->left_size = real_size;

          return (header *) new_block->data;
        }
        else {
          // go to free list
          size_t new_size = curr_size - real_size;
          set_size(current, new_size);

          size_t new_index = (new_size - ALLOC_HEADER_SIZE) / 8 - 1;
          if (new_index > N_LISTS -1){
            new_index = N_LISTS -1;
          }
          header *new_sentinel = &freelistSentinels[new_index];
          current->next->prev = current->prev;
          current->prev->next = current->next;

          new_sentinel->next->prev = current;
          current->next = new_sentinel->next;
          current->prev = new_sentinel;
          new_sentinel->next = current;

          header *new_block = (header *)((char *)current + new_size);
          set_state(new_block, ALLOCATED);

          new_block->left_size = new_size;
          set_size(new_block, real_size);
          get_right_header(new_block)->left_size = real_size;

          return (header *) new_block->data;
        }
      }
    }

    if (check == 1) {
      header *new_chunk = allocate_chunk(ARENA_SIZE);
      header *fence_post_new = get_left_header(new_chunk);
      header *fence_post_old = get_left_header(fence_post_new);
      header *left_new = get_left_header(fence_post_old);

      size_t old_size = get_size(left_new);

      if (fence_post_old == lastFencePost) {

        if (get_state(left_new) == UNALLOCATED) {
          set_size(left_new, get_size(left_new) + (2 * ALLOC_HEADER_SIZE) + get_size(new_chunk));
          lastFencePost = get_right_header(new_chunk);
          lastFencePost->left_size = get_size(left_new);

          if (old_size - ALLOC_HEADER_SIZE < N_LISTS * 8) {

            size_t new_index = ((get_size(left_new) - ALLOC_HEADER_SIZE) / 8) - 1;

            if (new_index > N_LISTS - 1) {
              new_index = N_LISTS - 1;
            }

            left_new->next->prev = left_new->prev;
            left_new->prev->next = left_new->next;

            header *new_sentinel = &freelistSentinels[new_index];

            new_sentinel->next->prev = left_new;
            left_new->next = new_sentinel->next;
            left_new->prev = new_sentinel;
            new_sentinel->next = left_new;

            return allocate_object(raw_size);
          }
          else {
            return allocate_object(raw_size);
          }
        }
        else if (get_state(left_new) == ALLOCATED) {
          set_size(fence_post_old, get_size(fence_post_old) + get_size(new_chunk) + get_size(fence_post_new));
          set_state(fence_post_old, UNALLOCATED);
          lastFencePost = get_right_header(new_chunk);
          lastFencePost->left_size = get_size(fence_post_old);

          size_t new_index = ((get_size(fence_post_old) - ALLOC_HEADER_SIZE) / 8) - 1;

          if (new_index > N_LISTS - 1) {
            new_index = N_LISTS - 1;
          }

          header *new_sentinel = &freelistSentinels[new_index];
          new_sentinel->next->prev = fence_post_old;
          fence_post_old->next = new_sentinel->next;
          fence_post_old->prev = new_sentinel;
          new_sentinel->next = fence_post_old;

          return allocate_object(raw_size);
        }
      }
      else {
        insert_os_chunk(get_left_header(new_chunk));
        set_state(new_chunk, UNALLOCATED);

        size_t new_index = ((get_size(new_chunk) - ALLOC_HEADER_SIZE) / 8) - 1;

        if (new_index > N_LISTS - 1) {
          new_index = N_LISTS - 1;
        }
        header *new_sentinel = &freelistSentinels[new_index];

        new_sentinel->next->prev = new_chunk;
        new_chunk->next = new_sentinel->next;
        new_chunk->prev = new_sentinel;
        new_sentinel->next = new_chunk;

        lastFencePost = get_right_header(new_chunk);
        lastFencePost->left_size = get_size(new_chunk);

        return allocate_object(raw_size);
      }

    }

    if (current != sentinel) {
      if (get_size(current) == real_size) {
        set_state(current, ALLOCATED);
        current->prev->next = current->next;
        current->next->prev = current->prev;
        return (header *)(current->data);
      }
      else if ((get_size(current) - real_size) < sizeof(header)) {
        // no split
        set_state(current, ALLOCATED);
        current->prev->next = current->next;
        current->next->prev = current->prev;
        return (header*)(current->data);
      }
      else {
        size_t new_size = get_size(current) - real_size;
        // Fix previous linked list that current was in
        current->prev->next = current->next;
        current->next->prev = current->prev;
        set_size(current, new_size);

        size_t new_index = ((new_size - ALLOC_HEADER_SIZE) / 8) - 1;
        if (new_index > N_LISTS - 1){
          new_index = N_LISTS-1;
        }

        header * new_list_sentinel = &freelistSentinels[new_index];

        // Insert current into the new linked list
        current->next = new_list_sentinel->next;
        current->prev = new_list_sentinel;
        new_list_sentinel->next->prev = current;
        new_list_sentinel->next = current;

        header *new_block = (header *)((char *)current + new_size);

        set_state(new_block, ALLOCATED);
        set_size(new_block, real_size);
        get_right_header(new_block)->left_size = real_size;

        new_block->left_size = new_size;


        return (header *) (new_block->data);
      }
      break;
    }

    index++;

    sentinel = &freelistSentinels[index];

    current = sentinel->next;

    //curr_size = get_size(current);

  }

  assert(false);
  exit(1);
}

/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */
static inline void deallocate_object(void * p) {
  // TODO implement deallocation
  if (p == NULL) {
    return;
  }

  header * current = ptr_to_header(p);

  if (get_state(current) == UNALLOCATED) {
    fprintf(stderr, "Double Free Detected\n");
    #line 577
    assert(false);

    abort();
    return;

  }

  header * left = get_left_header(current);
  header * right = get_right_header(current);

  int new_index = ((get_size(current) - ALLOC_HEADER_SIZE) / 8) - 1;

  if ((get_state(left) == UNALLOCATED) && (get_state(right) == UNALLOCATED)) {

    if (get_size(left) - ALLOC_HEADER_SIZE < N_LISTS * 8) {
      // remove right update current
      left->next->prev = left->prev;
      left->prev->next = left->next;

      right->next->prev = right->prev;
      right->prev->next = right->next;

      set_size(left, get_size(left) + get_size(current) + get_size(right));


      get_right_header(left)->left_size = get_size(left);

      new_index = ((get_size(left) - ALLOC_HEADER_SIZE) / 8) - 1;

      if (new_index > N_LISTS - 2) {
        new_index = N_LISTS - 1;
      }

      header * new_list_sentinel = &freelistSentinels[new_index];
      set_state(current, UNALLOCATED);
      current = left;

      // Insert current into the new linked list
      current->next = new_list_sentinel->next;
      current->prev = new_list_sentinel;
      current->next->prev = current;
      new_list_sentinel->next = current;

      return;
    }
    else {
      // Insert current into the new linked list
      set_state(current, UNALLOCATED);

      set_size(left, get_size(left) + get_size(current) + get_size(right));
      current = left;

      right->next->prev = right->prev;
      right->prev->next = right->next;

      get_right_header(current)->left_size = get_size(left);

      return;

    }
  }
  else if ((get_state(left) >= ALLOCATED) && (get_state(right) == UNALLOCATED)) {

    if (get_size(current) - ALLOC_HEADER_SIZE < N_LISTS * 8) {
      // remove right update current
      right->next->prev = right->prev;
      right->prev->next = right->next;

      set_size(current, get_size(right) + get_size(current));

      new_index = ((get_size(current) - ALLOC_HEADER_SIZE) / 8) - 1;

      if (new_index > N_LISTS - 2) {
        new_index = N_LISTS - 1;
      }

      header * new_list_sentinel = &freelistSentinels[new_index];

      // Insert current into the new linked list
      current->next = new_list_sentinel->next;
      current->prev = new_list_sentinel;
      new_list_sentinel->next->prev = current;
      new_list_sentinel->next = current;

      get_right_header(current)->left_size = get_size(current);

      set_state(current, UNALLOCATED);
      return;
    }
    else {
      set_size(current, get_size(right) + get_size(current));

      right->next->prev = right->prev;
      right->prev->next = right->next;

      get_right_header(current)->left_size = get_size(current);

      set_state(current, UNALLOCATED);
      return;
    }
  }
  else if ((get_state(left) == UNALLOCATED) && (get_state(right) >= ALLOCATED)) {

    if ((get_size(left) - ALLOC_HEADER_SIZE) < N_LISTS * 8) {
      // remove right update current
      left->next->prev = left->prev;
      left->prev->next = left->next;

      set_size(left, get_size(left) + get_size(current));

      new_index = ((get_size(left) - ALLOC_HEADER_SIZE) / 8) - 1;

      if (new_index > N_LISTS - 2) {
        new_index = N_LISTS - 1;
      }

      header * new_list_sentinel = &freelistSentinels[new_index];
      set_state(current, UNALLOCATED);
      current = left;

      // Insert current into the new linked list
      current->next = new_list_sentinel->next;
      current->prev = new_list_sentinel;
      current->next->prev = current;
      new_list_sentinel->next = current;
      right->left_size = get_size(current);

      return;
    }
    else {
      set_size(left, get_size(left) + get_size(current));
      set_state(current, UNALLOCATED);
      current = left;
      right->left_size = get_size(current);

      return;
    }
  }
  else {
    // ALL & ALL
    new_index = ((get_size(current) - ALLOC_HEADER_SIZE) / 8) - 1;

    if (new_index > N_LISTS - 2) {
      new_index = N_LISTS - 1;
    }

    header * new_list_sentinel = &freelistSentinels[new_index];

    // Insert current into the new linked list
    current->next = new_list_sentinel->next;
    current->prev = new_list_sentinel;
    new_list_sentinel->next->prev = current;
    new_list_sentinel->next = current;

    set_state(current, UNALLOCATED);
    return;
  }
  (void) p;
  assert(false);
  exit(1);
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}
/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {

  if (size == 0) {
    my_free(ptr);
    return NULL;
  }

  if (ptr == NULL) {
      void * mem = my_malloc(size);
      return mem;
  }

  header *curr = ptr_to_header(ptr);

  header *right = get_right_header(curr);

  if (get_state(right) == UNALLOCATED) {
    if (get_size(curr) + get_size(right) - ALLOC_HEADER_SIZE >= size) {
      set_state(right, ALLOCATED);
      set_size(curr, get_size(curr) + get_size(right));

      get_right_header(right)->left_size = get_size(curr);

      right->next->prev = right->prev;
      right->prev->next = right->next;

      return (header *)curr->data;
    }
  }

  if (size < get_size(curr)) {
    set_size(curr, size + ALLOC_HEADER_SIZE);

    get_right_header(curr)->left_size = get_size(curr);

    return (header *)curr->data;
  }

  void * mem = my_malloc(size);
  if (mem) {
    memcpy(mem, ptr, size);
    my_free(ptr);
  }
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}

/**
 * @brief Print just the block's size
 *
 * @param block The block to print
 */
void basic_print(header * block) {
	printf("[%zd] -> ", get_size(block));
}

/**
 * @brief Print just the block's size
 *
 * @param block The block to print
 */
void print_list(header * block) {
	printf("[%zd]\n", get_size(block));
}

/**
 * @brief return a string representing the allocation status
 *
 * @param allocated The allocation status field
 *
 * @return A string representing the allocation status
 */
static inline const char * allocated_to_string(char allocated) {
  switch(allocated) {
    case UNALLOCATED: 
      return "false";
    case ALLOCATED:
      return "true";
    case FENCEPOST:
      return "fencepost";
  }
  assert(false);
}

static bool check_color() {
  if (!check_env) {
    // genenv allows accessing environment varibles
    const char * var = getenv(MALLOC_COLOR);
    use_color = var != NULL && !strcmp(var, "1337_CoLoRs");
    check_env = true;
  }
  return use_color;
}

/**
 * @brief Change the tty color based on the block's allocation status
 *
 * @param block The block to print the allocation status of
 */
static void print_color(header * block) {
  if (!check_color()) {
    return;
  }

  switch(get_state(block)) {
    case UNALLOCATED:
      printf("\033[0;32m");
      break;
    case ALLOCATED:
      printf("\033[0;34m");
      break;
    case FENCEPOST:
      printf("\033[0;33m");
      break;
  }
}

static void clear_color() {
  if (check_color()) {
    printf("\033[0;0m");
  }
}

static inline bool is_sentinel(void * p) {
  for (int i = 0; i < N_LISTS; i++) {
    if (&freelistSentinels[i] == p) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Print the free list pointers if RELATIVE_POINTERS is set to true
 * then print the pointers as an offset from the base of the heap. This allows
 * for determinism in testing. 
 * (due to ASLR https://en.wikipedia.org/wiki/Address_space_layout_randomization#Linux)
 *
 * @param p The pointer to print
 */
void print_pointer(void * p) {
  if (is_sentinel(p)) {
    printf("SENTINEL");
  } else {
    if (RELATIVE_POINTERS) {
      printf("%04zd", p - base);
    } else {
      printf("%p", p);
    }
  }
}

/**
 * @brief Verbose printing of all of the metadata fields of each block
 *
 * @param block The block to print
 */
void print_object(header * block) {
  print_color(block);

  printf("[\n");
  printf("\taddr: ");
  print_pointer(block);
  puts("");
  printf("\tsize: %zd\n", get_size(block) );
  printf("\tleft_size: %zd\n", block->left_size);
  printf("\tallocated: %s\n", allocated_to_string(get_state(block)));
  if (!get_state(block)) {
    printf("\tprev: ");
    print_pointer(block->prev);
    puts("");

    printf("\tnext: ");
    print_pointer(block->next);
    puts("");
  }
  printf("]\n");

  clear_color();
}

/**
 * @brief Simple printer that just prints the allocation status of each block
 *
 * @param block The block to print
 */
void print_status(header * block) {
  print_color(block);
  switch(get_state(block)) {
    case UNALLOCATED:
      printf("[U]");
      break;
    case ALLOCATED:
      printf("[A]");
      break;
    case FENCEPOST:
      printf("[F]");
      break;
  }
  clear_color();
}

/*
static void print_bitmap() {
  printf("bitmap: [");
  for(int i = 0; i < N_LISTS; i++) {

    if ((freelist_bitmap[i >> 3] >> (i & 7)) & 1) {
      printf("\033[32m#\033[0m");
    } else {
      printf("\033[34m_\033[0m");
    }

    if (i % 8 == 7) {
      printf(" ");
    }

  }
  puts("]");
}
*/

/**
 * @brief Print a linked list between two nodes using a provided print function
 *
 * @param pf Function to perform the actual printing
 * @param start Node to start printing at
 * @param end Node to stop printing at
 */

void print_sublist(printFormatter pf, header * start, header * end) {  
  for (header * cur = start; cur != end; cur = cur->next) {
    pf(cur); 
  }
}

/**
 * @brief print the full freelist
 *
 * @param pf Function to perform the header printing
 */
void freelist_print(printFormatter pf) {
  if (!pf) {
    return;
  }

  for (size_t i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    if (freelist->next != freelist) {
      printf("L%zu: ", i);
      print_sublist(pf, freelist->next, freelist);
      puts("");
    }
    fflush(stdout);
  }
}

/**
 * @brief print the boundary tags from each chunk from the OS
 *
 * @param pf Function to perform the header printing
 */

void tags_print(printFormatter pf) {
  if (!pf) {
    return;
  }

  for (size_t i = 0; i < numOsChunks; i++) {
    header * chunk = osChunkList[i];
    pf(chunk);
    for (chunk = get_right_header(chunk);
         get_state(chunk) != FENCEPOST; 
         chunk = get_right_header(chunk)) {
        pf(chunk);
    }
    pf(chunk);
    fflush(stdout);
  }
}

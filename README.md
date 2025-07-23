# Custom Memory Allocator

A thread-safe implementation of dynamic memory allocation functions (malloc, free, calloc, realloc) using segregated free lists and boundary tag coalescing for efficient memory management.

## Overview

This project implements a custom memory allocator that serves as a replacement for the standard C library's memory management functions. The allocator uses advanced techniques including segregated free lists and immediate coalescing to minimize fragmentation and optimize performance.

## Features

- **Segregated Free Lists**: Multiple free lists organized by block size ranges for efficient allocation
- **Boundary Tag Coalescing**: Automatic merging of adjacent free blocks to reduce fragmentation
- **Thread Safety**: Mutex-protected operations for safe concurrent access
- **Memory Alignment**: Guarantees 8-byte alignment for all allocated blocks
- **Chunk Management**: Efficient handling of large memory chunks requested from the operating system
- **Verification System**: Built-in heap integrity checking and debugging capabilities

## API Reference

### Core Memory Management Functions

```c
void* my_malloc(size_t size);
void* my_calloc(size_t nmemb, size_t size);
void* my_realloc(void* ptr, size_t size);
void my_free(void* ptr);
```

### Heap Verification

```c
bool verify(void);
```

Verifies the structural integrity of the heap and free list organization.

## Architecture

### Memory Organization

The allocator organizes memory using a header-based approach where each block contains metadata including:

- Block size and allocation state
- Pointers for free list management (when unallocated)
- Left block size for efficient coalescing

### Free List Structure

The implementation maintains `N_LISTS` segregated free lists:

- **List 0**: Blocks sized 8-15 bytes
- **List 1**: Blocks sized 16-23 bytes
- **List i**: Blocks sized `(i*8)` to `((i+1)*8-1)` bytes
- **List N-1**: Blocks sized `≥ (N-1)*8` bytes (catch-all for large blocks)

### Block States

- `ALLOCATED`: Block is currently in use
- `UNALLOCATED`: Block is available for allocation
- `FENCEPOST`: Boundary marker preventing invalid coalescing operations

## Implementation Details

### Allocation Algorithm

1. **Size Normalization**: Round requested size up to 8-byte alignment with 16-byte minimum
2. **List Selection**: Determine appropriate free list based on total block size
3. **Block Search**: Find suitable block, preferring exact fits
4. **Block Splitting**: Split oversized blocks when remainder is sufficient for new block
5. **OS Requests**: Allocate new chunks from operating system when no suitable blocks exist

### Deallocation and Coalescing

The deallocator implements immediate coalescing using boundary tags:

1. **Neighbor Analysis**: Check allocation state of left and right adjacent blocks
2. **Coalescing**: Merge with free neighbors to create larger contiguous blocks
3. **List Management**: Insert coalesced block into appropriate free list
4. **Error Detection**: Identify and handle double-free attempts

### Coalescing Scenarios

- **Both neighbors free**: Merge all three blocks
- **Left neighbor free**: Merge with left block
- **Right neighbor free**: Merge with right block  
- **No free neighbors**: Insert block directly into free list

## Build Instructions

### Debug Build
```bash
gcc -DDEBUG -g -Wall -Wextra -pthread -o allocator_test myMalloc.c test.c
```

### Release Build
```bash
gcc -O2 -Wall -Wextra -pthread -o allocator_test myMalloc.c test.c
```

### Build with Address Sanitizer
```bash
gcc -fsanitize=address -g -Wall -Wextra -pthread -o allocator_test myMalloc.c test.c
```

## Testing and Verification

### Built-in Verification

The allocator includes comprehensive integrity checking:

```c
// Verify heap structure
if (!verify()) {
    fprintf(stderr, "Heap corruption detected\n");
    exit(1);
}
```

### Verification Components

- **Cycle Detection**: Identifies circular references in free lists using Floyd's algorithm
- **Pointer Consistency**: Validates bidirectional pointer relationships
- **Boundary Tag Validation**: Ensures size consistency between adjacent blocks
- **Double-free Protection**: Detects attempts to free already-freed blocks

## Performance Characteristics

### Time Complexity
- **Allocation**: O(n) worst case, O(1) average case
- **Deallocation**: O(1) constant time
- **Reallocation**: O(n) for copying, O(1) for in-place expansion

### Space Complexity
- **Overhead**: 8 bytes per allocated block (header metadata)
- **Fragmentation**: Minimized through immediate coalescing and size-segregated lists

### Memory Alignment
- All blocks aligned to 8-byte boundaries
- Minimum allocation size of 16 bytes (excluding header)

## Thread Safety

Thread safety is implemented using POSIX mutexes:

```c
pthread_mutex_lock(&mutex);
// Critical section operations
pthread_mutex_unlock(&mutex);
```

All public API functions acquire the global mutex before performing heap operations.

## Error Handling

### Allocation Failures
- Returns `NULL` when insufficient memory available
- Handles zero-size allocation requests appropriately

### Deallocation Errors
- **Double-free Detection**: Terminates program with diagnostic message
- **Invalid Pointer Handling**: Gracefully handles `NULL` pointer frees

### Reallocation Edge Cases
- Size zero treated as free operation
- `NULL` pointer treated as malloc operation
- Efficient in-place expansion when possible

## Use Cases

This allocator is designed for:

- **Educational Purposes**: Understanding memory management implementation
- **Research Applications**: Custom allocation strategies and analysis
- **Embedded Systems**: Predictable memory management behavior
- **Performance Testing**: Comparing allocation strategies

## Current Status

This implementation contains several areas marked for completion:

- Allocation algorithm optimization in large block handling
- Enhanced chunk coalescing for OS-level memory management
- Additional error recovery mechanisms

## Academic Context

Developed as part of CS252 (Systems Programming) coursework to demonstrate understanding of:

- Dynamic memory management techniques
- Data structure implementation and optimization
- System-level programming concepts
- Concurrent programming with thread safety

## Technical References

- Knuth, Donald E. "The Art of Computer Programming, Volume 1"
- Wilson, Paul R. "Uniprocessor Garbage Collection Techniques"
- Johnstone, Mark S. "The Memory Fragmentation Problem"

## License

This project is developed for academic purposes under CS252 coursework guidelines.

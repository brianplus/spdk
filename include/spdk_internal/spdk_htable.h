/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * SPDK Hash Table
 */

#ifndef SPDK_HTABLE_H
#define SPDK_HTABLE_H

#include "spdk/stdinc.h"
#include "spdk/queue.h"
#include "spdk/util.h"

#define SPDK_HTABLE_BUCKET(type) LIST_HEAD(, type) 
#define SPDK_HTABLE_ENTRY(type) LIST_ENTRY(type)

#define SPDK_HTABLE_DECLARE(name, type, max_hash) \
	struct name { \
		SPDK_HTABLE_BUCKET(type) buckets[max_hash]; \
	}

#define SPDK_HTABLE_INITIALIZER(name, max_hash) \
	{ \
		.buckets =  { [0 ... max_hash - 1] = LIST_HEAD_INITIALIZER(junk) }; \
	}

/**
 * spdk_htable_size - get size of a hash table
 * 
 * \param ht hashtable
 * 
 * \return Number of the hash table's buckets
 */
#define spdk_htable_size(ht) SPDK_COUNTOF((ht)->buckets)

/**
 * spdk_htable_empty - check whether a hash table is empty
 * 
 * \param ht hashtable
 * 
  * \return true if the hash table is empty, othwerwise - false.
 */
#define spdk_htable_empty(ht) \
	({ \
		bool empty = false; \
		size_t i; \
		for (i = 0; i < spdk_htable_size(ht); i++) { \
			if (!LIST_EMPTY(&(ht)->buckets[i])) { \
				empty = true; \
				break; \
			} \
		}; \
		empty; \
	})

/**
 * spdk_htable_init - initialize a hash table
 * 
 * \param ht hashtable to be initialized
 */
#define spdk_htable_init(ht) \
	do { \
		size_t i; \
		for (i = 0; i < spdk_htable_size(ht); i++) { \
			LIST_INIT(&(ht)->buckets[i]); \
		} \
	} while (0)

/**
 * spdk_htable_add - add an object to a hashtable
 * 
 * \param ht hashtable
 * \param node the node to be added
 * \param field the name of the @node object field of SPDK_HTABLE_ENTRY type
 * \param key: the key of the object to be added
*/
#define spdk_htable_add(ht, node, field, key) \
	do { \
		assert(key < spdk_htable_size(ht)); \
		LIST_INSERT_HEAD(&(ht)->buckets[key], node, field); \
	} while (0)

/**
 * spdk_htable_del - remove an object from a hashtable
 * 
 * \param node the node to be removed
 * \param field the name of the @node object field of SPDK_HTABLE_ENTRY type
*/
#define spdk_htable_del(node, field) \
	do { \
		LIST_REMOVE(node, field); \
	} while (0)

/**
 * spdk_htable_foreach - iterate over a hashtable
 * 
 * \param ht hashtable
 * \param bkt size_t to use as bucket loop cursor
 * \param node the type * variable to use as a loop cursor for each entry
 * \param field the name of the @node object field of SPDK_HTABLE_ENTRY type
 */
#define spdk_htable_foreach(ht, bkt, node, field) \
 	for ((bkt) = 0, (node) = NULL; (bkt) < spdk_htable_size(ht); (bkt)++) \
		LIST_FOREACH(node, &(ht)->buckets[bkt], field)

/**
 * spdk_htable_foreach_safe - iterate over a hashtable safe against removal of
 * \param ht hashtable
 * \param bkt size_t to use as bucket loop cursor
 * \param node a variable of type * to use as a loop cursor for each entry
 * \param field the name of the @node object field of SPDK_HTABLE_ENTRY type
 * \param tvar a variable of type * used for temporary storage
 */
#define spdk_htable_foreach_safe(ht, bkt, node, field, tvar) \
 	for ((bkt) = 0, (node) = NULL; (bkt) < spdk_htable_size(ht); (bkt)++) \
		LIST_FOREACH_SAFE(node, &(ht)->buckets[bkt], field, tvar)

#endif /* SPDK_HTABLE_H */

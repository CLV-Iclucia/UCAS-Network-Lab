#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>

struct list_head {
	struct list_head *next, *prev;
};

#define list_empty(list) ((list)->next == (list))

#define list_entry(ptr, type, member) \
	(type *)((char *)ptr - offsetof(type, member))

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = list_entry(pos->member.next, typeof(*pos), member)) 

#define list_for_each_safe(pos, q, head) \
	for (pos = (head)->next, q = pos->next; pos != (head); \
			pos = q, q = pos->next)

#define list_for_each_entry_safe(pos, q, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member), \
			q = list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = q, q = list_entry(pos->member.next, typeof(*q), member))

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

static inline void init_list_head(struct list_head *list)
{
	list->next = list->prev = list;
}

static inline void list_insert(struct list_head *new_node,
		struct list_head *prev,
		struct list_head *next)
{
	next->prev = new_node;
	prev->next = new_node;
	new_node->next = next;
	new_node->prev = prev;
}

static inline void list_delete_entry(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

static inline void list_add_tail(struct list_head *new_node, struct list_head *head)
{
	list_insert(new_node, head->prev, head);
}

#endif

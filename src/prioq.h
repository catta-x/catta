#ifndef fooprioqhfoo
#define fooprioqhfoo

/***
  This file is part of catta.

  catta is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  catta is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with catta; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

typedef struct CattaPrioQueue CattaPrioQueue;
typedef struct CattaPrioQueueNode CattaPrioQueueNode;

typedef int (*CattaPQCompareFunc)(const void* a, const void* b);

struct CattaPrioQueue {
    CattaPrioQueueNode *root, *last;
    unsigned n_nodes;
    CattaPQCompareFunc compare;
};

struct CattaPrioQueueNode {
    CattaPrioQueue *queue;
    void* data;
    unsigned x, y;
    CattaPrioQueueNode *left, *right, *parent, *next, *prev;
};

CattaPrioQueue* catta_prio_queue_new(CattaPQCompareFunc compare);
void catta_prio_queue_free(CattaPrioQueue *q);

CattaPrioQueueNode* catta_prio_queue_put(CattaPrioQueue *q, void* data);
void catta_prio_queue_remove(CattaPrioQueue *q, CattaPrioQueueNode *n);

void catta_prio_queue_shuffle(CattaPrioQueue *q, CattaPrioQueueNode *n);

#endif

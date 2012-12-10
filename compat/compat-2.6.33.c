/*
 * Copyright 2009	Hauke Mehrtens <hauke@hauke-m.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Compatibility file for Linux wireless for kernels 2.6.33.
 */

#include <linux/compat.h>
#include <linux/autoconf.h>

#if defined(CONFIG_PCCARD) || defined(CONFIG_PCCARD_MODULE)

/**
 * pccard_loop_tuple() - loop over tuples in the CIS
 * @s:		the struct pcmcia_socket where the card is inserted
 * @function:	the device function we loop for
 * @code:	which CIS code shall we look for?
 * @parse:	buffer where the tuple shall be parsed (or NULL, if no parse)
 * @priv_data:	private data to be passed to the loop_tuple function.
 * @loop_tuple:	function to call for each CIS entry of type @function. IT
 *		gets passed the raw tuple, the paresed tuple (if @parse is
 *		set) and @priv_data.
 *
 * pccard_loop_tuple() loops over all CIS entries of type @function, and
 * calls the @loop_tuple function for each entry. If the call to @loop_tuple
 * returns 0, the loop exits. Returns 0 on success or errorcode otherwise.
 */
int pccard_loop_tuple(struct pcmcia_socket *s, unsigned int function,
		      cisdata_t code, cisparse_t *parse, void *priv_data,
		      int (*loop_tuple) (tuple_t *tuple,
					 cisparse_t *parse,
					 void *priv_data))
{
	tuple_t tuple;
	cisdata_t *buf;
	int ret;

	buf = kzalloc(256, GFP_KERNEL);
	if (buf == NULL) {
		dev_printk(KERN_WARNING, &s->dev, "no memory to read tuple\n");
		return -ENOMEM;
	}

	tuple.TupleData = buf;
	tuple.TupleDataMax = 255;
	tuple.TupleOffset = 0;
	tuple.DesiredTuple = code;
	tuple.Attributes = 0;

	ret = pccard_get_first_tuple(s, function, &tuple);
	while (!ret) {
		if (pccard_get_tuple_data(s, &tuple))
			goto next_entry;

		if (parse)
			if (pcmcia_parse_tuple(&tuple, parse))
				goto next_entry;

		ret = loop_tuple(&tuple, parse, priv_data);
		if (!ret)
			break;

next_entry:
		ret = pccard_get_next_tuple(s, function, &tuple);
	}

	kfree(buf);
	return ret;
}
EXPORT_SYMBOL_GPL(pccard_loop_tuple);
/* Source: drivers/pcmcia/cistpl.c */

#if defined(CONFIG_PCMCIA) || defined(CONFIG_PCMCIA_MODULE)

struct pcmcia_loop_mem {
	struct pcmcia_device *p_dev;
	void *priv_data;
	int (*loop_tuple) (struct pcmcia_device *p_dev,
			   tuple_t *tuple,
			   void *priv_data);
};

/**
 * pcmcia_do_loop_tuple() - internal helper for pcmcia_loop_config()
 *
 * pcmcia_do_loop_tuple() is the internal callback for the call from
 * pcmcia_loop_tuple() to pccard_loop_tuple(). Data is transferred
 * by a struct pcmcia_cfg_mem.
 */
static int pcmcia_do_loop_tuple(tuple_t *tuple, cisparse_t *parse, void *priv)
{
	struct pcmcia_loop_mem *loop = priv;

	return loop->loop_tuple(loop->p_dev, tuple, loop->priv_data);
};

/**
 * pcmcia_loop_tuple() - loop over tuples in the CIS
 * @p_dev:	the struct pcmcia_device which we need to loop for.
 * @code:	which CIS code shall we look for?
 * @priv_data:	private data to be passed to the loop_tuple function.
 * @loop_tuple:	function to call for each CIS entry of type @function. IT
 *		gets passed the raw tuple and @priv_data.
 *
 * pcmcia_loop_tuple() loops over all CIS entries of type @function, and
 * calls the @loop_tuple function for each entry. If the call to @loop_tuple
 * returns 0, the loop exits. Returns 0 on success or errorcode otherwise.
 */
int pcmcia_loop_tuple(struct pcmcia_device *p_dev, cisdata_t code,
		      int (*loop_tuple) (struct pcmcia_device *p_dev,
					 tuple_t *tuple,
					 void *priv_data),
		      void *priv_data)
{
	struct pcmcia_loop_mem loop = {
		.p_dev = p_dev,
		.loop_tuple = loop_tuple,
		.priv_data = priv_data};

	return pccard_loop_tuple(p_dev->socket, p_dev->func, code, NULL,
				 &loop, pcmcia_do_loop_tuple);
}
EXPORT_SYMBOL_GPL(pcmcia_loop_tuple);
/* Source: drivers/pcmcia/pcmcia_resource.c */

#endif /* CONFIG_PCMCIA */

#endif /* CONFIG_PCCARD */

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) % BITS_PER_LONG))

void bitmap_set(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BIT_WORD(start);
	const int size = start + nr;
	int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_set >= 0) {
		*p |= mask_to_set;
		nr -= bits_to_set;
		bits_to_set = BITS_PER_LONG;
		mask_to_set = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_set &= BITMAP_LAST_WORD_MASK(size);
		*p |= mask_to_set;
	}
}
EXPORT_SYMBOL(bitmap_set);

void bitmap_clear(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BIT_WORD(start);
	const int size = start + nr;
	int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_clear >= 0) {
		*p &= ~mask_to_clear;
		nr -= bits_to_clear;
		bits_to_clear = BITS_PER_LONG;
		mask_to_clear = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
		*p &= ~mask_to_clear;
	}
}
EXPORT_SYMBOL(bitmap_clear);

/*
 * bitmap_find_next_zero_area - find a contiguous aligned zero area
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @align_mask: Alignment mask for zero area
 *
 * The @align_mask should be one less than a power of 2; the effect is that
 * the bit offset of all zero areas this function finds is multiples of that
 * power of 2. A @align_mask of 0 means no alignment is required.
 */
unsigned long bitmap_find_next_zero_area(unsigned long *map,
					 unsigned long size,
					 unsigned long start,
					 unsigned int nr,
					 unsigned long align_mask)
{
	unsigned long index, end, i;
again:
	index = find_next_zero_bit(map, size, start);

	/* Align allocation */
	index = __ALIGN_MASK(index, align_mask);

	end = index + nr;
	if (end > size)
		return end;
	i = find_next_bit(map, end, index);
	if (i < end) {
		start = i + 1;
		goto again;
	}
	return index;
}
EXPORT_SYMBOL(bitmap_find_next_zero_area);

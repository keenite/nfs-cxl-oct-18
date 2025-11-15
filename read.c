// SPDX-License-Identifier: GPL-2.0-only
/*
 * linux/fs/nfs/read.c
 *
 * Block I/O for NFS
 *
 * Partial copy of Linus' read cache modifications to fs/nfs/file.c
 * modified for async RPC by okir@monad.swb.de
 */

#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagemap.h>
#include <linux/sunrpc/clnt.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/module.h>

#include <linux/hashtable.h>

#include <linux/io.h>
#include <linux/types.h>
#include <linux/init.h>

#include "nfs4_fs.h"
#include "internal.h"
#include "iostat.h"
#include "fscache.h"
#include "pnfs.h"
#include "nfstrace.h"

#define NFSDBG_FACILITY		NFSDBG_PAGECACHE

static const struct nfs_pgio_completion_ops nfs_async_read_completion_ops;
static const struct nfs_rw_ops nfs_rw_read_ops;

static struct kmem_cache *nfs_rdata_cachep;


///////////////////////////////////////////////////////////////////////
#define CXL_ADDR 0x410000000
#define REGION_SIZE (1UL << 30)
#define MAX_PAYLOAD_SIZE 32

#define CXL_HASH_BITS_SIZE 1
#define BUCKET_COUNT (1 << CXL_HASH_BITS_SIZE)

#define CXL_HASH_BITS ilog2(BUCKET_COUNT)   // HASH_BITS(name)

/* Use hash_32 when possible to allow for fast 32bit hashing in 64bit kernels. */
#define cxl_hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))

#define cxl_hlist_entry_safe(ptr, type, member, base)                \
	({                                                           \
		typeof(ptr) ____ptr =                                \
			(struct hlist_node*)((unsigned long)(ptr) + (unsigned long)base);  \
		____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

#define cxl_hlist_for_each_entry(pos, head, member, base)                      \
	for (pos = cxl_hlist_entry_safe((head)->first, typeof(*(pos)), member, \
					base);                                 \
	     pos != base;                                                      \
	     pos = cxl_hlist_entry_safe((pos)->member.next, typeof(*(pos)),    \
					member, base))

#define cxl_hash_for_each_possible(name, obj, member, key, base)               \
	cxl_hlist_for_each_entry(obj, &name[cxl_hash_min(key, CXL_HASH_BITS)], \
				 member, base)

static unsigned allocate_index = 1u;

struct cxl_entry {
    struct hlist_node node; // The all-important hash table node
    u32 key;            // The key we will hash on
    char payload[MAX_PAYLOAD_SIZE];   // Some example data
};

// Mapped CXL hashtable base address
void  *cxl_base = NULL;

// The hashtable header address.
struct hlist_head __iomem (*cxl_ht)[BUCKET_COUNT];

// The memory address.
void  *data_base = NULL;

#define ADDR_TO_OFFSET_NODE_2(addr, base) \
	(struct hlist_node **)(((void*)addr - (void*)base))

#define ADDR_TO_OFFSET_NODE_1(addr, base) \
	(struct hlist_node *)(((void*)addr - (void*)base))

#define ADDR_TO_OFFSET_HEAD(addr, base) \
	(struct hlist_node **)(((void*)addr - (void*)base))

#define OFFSET_TO_ADDR_NODE(offset, base) \
	(struct hlist_node *)(((unsigned long)offset + (unsigned long)base))

static inline void cxl_hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *old_first = h->first;
	//pr_info(">>>> @@@"
	//	"base[%px] "
	//	"data_base[%px] "
	//	"new_node[%px], "
	//	"head[%px]",
	//	cxl_base, 
	//	data_base, 
	//	n, 
	//	h);
	//pr_info(
	//	"head->first[%px], "
	//	"&h->first[%px] "
	//	"&n->next[%px]",
	//	h->first, &h->first, &n->next);
	// Insert N to the head of the bucket. The new item next node will be the head
	//  of the list.
	WRITE_ONCE(n->next, old_first);

	// If the first not empty, make the old first point holder to &n->next.
	if (old_first)
		WRITE_ONCE((OFFSET_TO_ADDR_NODE(old_first, cxl_base))->pprev,
			   ADDR_TO_OFFSET_NODE_2(&n->next, cxl_base));

	// head first item is n.
	WRITE_ONCE(h->first, ADDR_TO_OFFSET_NODE_1(n, cxl_base));

	// n's holder is &h->first.
	WRITE_ONCE(n->pprev, ADDR_TO_OFFSET_NODE_2(&h->first, cxl_base));
	// pr_info("<<< @@@ "
	// 	"n->next[%px] "
	// 	"first->pprev[%px] "
	// 	"h->first[%px] "
	// 	"n->pprev[%px]",
	// 	(void *)n->next,
	// 	old_first != NULL ?
	// 		(void *)(OFFSET_TO_ADDR_NODE(old_first, cxl_base))
	// 			->pprev :
	// 		NULL,
	// 	(void *)h->first, (void *)n->pprev);
}

static void cxl_mem_test(void) {
	struct cxl_entry *obj =
		(struct cxl_entry *)(data_base +
				     allocate_index * sizeof(struct cxl_entry));
	sprintf(obj->payload, "Hello %u", allocate_index);
	INIT_HLIST_NODE(&obj->node);
	// pr_info("@@@@@@Read %u index to the memory, the obj [%px] size[%zu]",
	// 	allocate_index, obj, sizeof(struct cxl_entry));

	obj->key = allocate_index++;

	cxl_hlist_add_head(&obj->node,
			   cxl_ht[cxl_hash_min(obj->key, CXL_HASH_BITS)]);
	pr_info("=================Finished the mem test");
}

static void cxl_mem_read1(void) {
	struct cxl_entry* obj = NULL;
	unsigned key1 = 1u;
	int count = 0;
	cxl_hash_for_each_possible(*cxl_ht, obj, node, key1, cxl_base) {
		pr_info("@@@@Current index %u data: %s obj_addr[%px], next[%px]",
			obj->key, obj->payload, obj, obj->node.next);
		if (count++ ==10) {
			pr_info("@@@@ Count reach 10");
			break;
		}
	}
}

static void cxl_mem_read2(void) {
	struct cxl_entry* obj = NULL;
	unsigned key1 = 2u;
	int count = 0;
	cxl_hash_for_each_possible(*cxl_ht, obj, node, key1, cxl_base) {
		pr_info("@@@@Current index %u data: %s", obj->key, obj->payload);
		if (count++ ==10) {
			pr_info("@@@@ Count reach 10");
			break;
		}
	}
}

static void cxl_mem_init(void) {
	if (cxl_base != NULL) return;
	cxl_base = memremap(CXL_ADDR, REGION_SIZE, MEMREMAP_WB);
	if (!cxl_base) {
		pr_err("@@@@@@Failed to memory map !!!!!!!!!");
	}
	cxl_ht = (struct hlist_head (*)[BUCKET_COUNT])cxl_base;
	for (unsigned int i = 0u; i < BUCKET_COUNT; i++) {
		cxl_ht[i]->first = NULL; // Checks the HLIST_HEAD_INIT.
		INIT_HLIST_HEAD(cxl_ht[i]);
	}
	pr_info("@@@@@ bucket_count[%d] offset[%lu]", BUCKET_COUNT,
		sizeof(struct hlist_head) * BUCKET_COUNT);
	data_base = cxl_base + sizeof(struct hlist_head) * BUCKET_COUNT;
}


//////////////////////////////////////////////////////////////////////

static struct nfs_pgio_header *nfs_readhdr_alloc(void)
{
	struct nfs_pgio_header *p = kmem_cache_zalloc(nfs_rdata_cachep, GFP_KERNEL);

	if (p)
		p->rw_mode = FMODE_READ;
	return p;
}

static void nfs_readhdr_free(struct nfs_pgio_header *rhdr)
{
	kmem_cache_free(nfs_rdata_cachep, rhdr);
}

static int nfs_return_empty_folio(struct folio *folio)
{
	folio_zero_segment(folio, 0, folio_size(folio));
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	return 0;
}

void nfs_pageio_init_read(struct nfs_pageio_descriptor *pgio,
			      struct inode *inode, bool force_mds,
			      const struct nfs_pgio_completion_ops *compl_ops)
{
	struct nfs_server *server = NFS_SERVER(inode);
	const struct nfs_pageio_ops *pg_ops = &nfs_pgio_rw_ops;

#ifdef CONFIG_NFS_V4_1
	if (server->pnfs_curr_ld && !force_mds)
		pg_ops = server->pnfs_curr_ld->pg_read_ops;
#endif
	nfs_pageio_init(pgio, inode, pg_ops, compl_ops, &nfs_rw_read_ops,
			server->rsize, 0);
}
EXPORT_SYMBOL_GPL(nfs_pageio_init_read);

static void nfs_pageio_complete_read(struct nfs_pageio_descriptor *pgio)
{
	struct nfs_pgio_mirror *pgm;
	unsigned long npages;

	nfs_pageio_complete(pgio);

	/* It doesn't make sense to do mirrored reads! */
	WARN_ON_ONCE(pgio->pg_mirror_count != 1);

	pgm = &pgio->pg_mirrors[0];
	NFS_I(pgio->pg_inode)->read_io += pgm->pg_bytes_written;
	npages = (pgm->pg_bytes_written + PAGE_SIZE - 1) >> PAGE_SHIFT;
	nfs_add_stats(pgio->pg_inode, NFSIOS_READPAGES, npages);
}


void nfs_pageio_reset_read_mds(struct nfs_pageio_descriptor *pgio)
{
	struct nfs_pgio_mirror *mirror;

	if (pgio->pg_ops && pgio->pg_ops->pg_cleanup)
		pgio->pg_ops->pg_cleanup(pgio);

	pgio->pg_ops = &nfs_pgio_rw_ops;

	/* read path should never have more than one mirror */
	WARN_ON_ONCE(pgio->pg_mirror_count != 1);

	mirror = &pgio->pg_mirrors[0];
	mirror->pg_bsize = NFS_SERVER(pgio->pg_inode)->rsize;
}
EXPORT_SYMBOL_GPL(nfs_pageio_reset_read_mds);

static void nfs_readpage_release(struct nfs_page *req, int error)
{
	struct inode *inode = d_inode(nfs_req_openctx(req)->dentry);
	struct folio *folio = nfs_page_to_folio(req);

	dprintk("NFS: read done (%s/%llu %d@%lld)\n", inode->i_sb->s_id,
		(unsigned long long)NFS_FILEID(inode), req->wb_bytes,
		(long long)req_offset(req));

	if (nfs_error_is_fatal_on_server(error) && error != -ETIMEDOUT)
		folio_set_error(folio);
	if (nfs_page_group_sync_on_bit(req, PG_UNLOCKPAGE)) {
		if (folio_test_uptodate(folio))
			nfs_fscache_write_page(inode, &folio->page);
		folio_unlock(folio);
	}
	nfs_release_request(req);
}

struct nfs_readdesc {
	struct nfs_pageio_descriptor pgio;
	struct nfs_open_context *ctx;
};

static void nfs_page_group_set_uptodate(struct nfs_page *req)
{
	if (nfs_page_group_sync_on_bit(req, PG_UPTODATE))
		folio_mark_uptodate(nfs_page_to_folio(req));
}

static void nfs_read_completion(struct nfs_pgio_header *hdr)
{
	unsigned long bytes = 0;
	int error;

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags))
		goto out;
	while (!list_empty(&hdr->pages)) {
		struct nfs_page *req = nfs_list_entry(hdr->pages.next);
		struct folio *folio = nfs_page_to_folio(req);
		unsigned long start = req->wb_pgbase;
		unsigned long end = req->wb_pgbase + req->wb_bytes;

		if (test_bit(NFS_IOHDR_EOF, &hdr->flags)) {
			/* note: regions of the page not covered by a
			 * request are zeroed in readpage_async_filler */
			if (bytes > hdr->good_bytes) {
				/* nothing in this request was good, so zero
				 * the full extent of the request */
				folio_zero_segment(folio, start, end);

			} else if (hdr->good_bytes - bytes < req->wb_bytes) {
				/* part of this request has good bytes, but
				 * not all. zero the bad bytes */
				start += hdr->good_bytes - bytes;
				WARN_ON(start < req->wb_pgbase);
				folio_zero_segment(folio, start, end);
			}
		}
		error = 0;
		bytes += req->wb_bytes;
		if (test_bit(NFS_IOHDR_ERROR, &hdr->flags)) {
			if (bytes <= hdr->good_bytes)
				nfs_page_group_set_uptodate(req);
			else {
				error = hdr->error;
				xchg(&nfs_req_openctx(req)->error, error);
			}
		} else
			nfs_page_group_set_uptodate(req);
		nfs_list_remove_request(req);
		nfs_readpage_release(req, error);
	}
out:
	hdr->release(hdr);
}

static void nfs_initiate_read(struct nfs_pgio_header *hdr,
			      struct rpc_message *msg,
			      const struct nfs_rpc_ops *rpc_ops,
			      struct rpc_task_setup *task_setup_data, int how)
{
	rpc_ops->read_setup(hdr, msg);
	trace_nfs_initiate_read(hdr);
}

static void
nfs_async_read_error(struct list_head *head, int error)
{
	struct nfs_page	*req;

	while (!list_empty(head)) {
		req = nfs_list_entry(head->next);
		nfs_list_remove_request(req);
		nfs_readpage_release(req, error);
	}
}

static const struct nfs_pgio_completion_ops nfs_async_read_completion_ops = {
	.error_cleanup = nfs_async_read_error,
	.completion = nfs_read_completion,
};

/*
 * This is the callback from RPC telling us whether a reply was
 * received or some error occurred (timeout or socket shutdown).
 */
static int nfs_readpage_done(struct rpc_task *task,
			     struct nfs_pgio_header *hdr,
			     struct inode *inode)
{
	int status = NFS_PROTO(inode)->read_done(task, hdr);
	if (status != 0)
		return status;

	nfs_add_stats(inode, NFSIOS_SERVERREADBYTES, hdr->res.count);
	trace_nfs_readpage_done(task, hdr);

	if (task->tk_status == -ESTALE) {
		nfs_set_inode_stale(inode);
		nfs_mark_for_revalidate(inode);
	}
	return 0;
}

static void nfs_readpage_retry(struct rpc_task *task,
			       struct nfs_pgio_header *hdr)
{
	struct nfs_pgio_args *argp = &hdr->args;
	struct nfs_pgio_res  *resp = &hdr->res;

	/* This is a short read! */
	nfs_inc_stats(hdr->inode, NFSIOS_SHORTREAD);
	trace_nfs_readpage_short(task, hdr);

	/* Has the server at least made some progress? */
	if (resp->count == 0) {
		nfs_set_pgio_error(hdr, -EIO, argp->offset);
		return;
	}

	/* For non rpc-based layout drivers, retry-through-MDS */
	if (!task->tk_ops) {
		hdr->pnfs_error = -EAGAIN;
		return;
	}

	/* Yes, so retry the read at the end of the hdr */
	hdr->mds_offset += resp->count;
	argp->offset += resp->count;
	argp->pgbase += resp->count;
	argp->count -= resp->count;
	resp->count = 0;
	resp->eof = 0;
	rpc_restart_call_prepare(task);
}

static void nfs_readpage_result(struct rpc_task *task,
				struct nfs_pgio_header *hdr)
{
	if (hdr->res.eof) {
		loff_t pos = hdr->args.offset + hdr->res.count;
		unsigned int new = pos - hdr->io_start;

		if (hdr->good_bytes > new) {
			hdr->good_bytes = new;
			set_bit(NFS_IOHDR_EOF, &hdr->flags);
			clear_bit(NFS_IOHDR_ERROR, &hdr->flags);
		}
	} else if (hdr->res.count < hdr->args.count)
		nfs_readpage_retry(task, hdr);
}

static int readpage_async_filler(struct nfs_readdesc *desc, struct folio *folio)
{
	struct inode *inode = folio_file_mapping(folio)->host;
	struct nfs_server *server = NFS_SERVER(inode);
	size_t fsize = folio_size(folio);
	unsigned int rsize = server->rsize;
	struct nfs_page *new;
	unsigned int len, aligned_len;
	int error;

	len = nfs_folio_length(folio);
	if (len == 0)
		return nfs_return_empty_folio(folio);

	aligned_len = min_t(unsigned int, ALIGN(len, rsize), fsize);

	if (!IS_SYNC(inode)) {
		error = nfs_fscache_read_page(inode, &folio->page);
		if (error == 0)
			goto out_unlock;
	}

	new = nfs_page_create_from_folio(desc->ctx, folio, 0, aligned_len);
	if (IS_ERR(new))
		goto out_error;

	if (len < fsize)
		folio_zero_segment(folio, len, fsize);
	if (!nfs_pageio_add_request(&desc->pgio, new)) {
		nfs_list_remove_request(new);
		error = desc->pgio.pg_error;
		nfs_readpage_release(new, error);
		goto out;
	}
	return 0;
out_error:
	error = PTR_ERR(new);
out_unlock:
	folio_unlock(folio);
out:
	return error;
}

/*
 * Read a page over NFS.
 * We read the page synchronously in the following case:
 *  -	The error flag is set for this page. This happens only when a
 *	previous async read operation failed.
 */
int nfs_read_folio(struct file *file, struct folio *folio)
{
	struct nfs_readdesc desc;
	struct inode *inode = file_inode(file);
	int ret;

	trace_nfs_aop_readpage(inode, folio);
	nfs_inc_stats(inode, NFSIOS_VFSREADPAGE);
	task_io_account_read(folio_size(folio));

	/*
	 * Try to flush any pending writes to the file..
	 *
	 * NOTE! Because we own the folio lock, there cannot
	 * be any new pending writes generated at this point
	 * for this folio (other folios can be written to).
	 */
	ret = nfs_wb_folio(inode, folio);
	if (ret)
		goto out_unlock;
	if (folio_test_uptodate(folio))
		goto out_unlock;

	ret = -ESTALE;
	if (NFS_STALE(inode))
		goto out_unlock;

	desc.ctx = get_nfs_open_context(nfs_file_open_context(file));

	xchg(&desc.ctx->error, 0);
	nfs_pageio_init_read(&desc.pgio, inode, false,
			     &nfs_async_read_completion_ops);

	ret = readpage_async_filler(&desc, folio);
	if (ret)
		goto out;

	nfs_pageio_complete_read(&desc.pgio);
	ret = desc.pgio.pg_error < 0 ? desc.pgio.pg_error : 0;
	if (!ret) {
		ret = folio_wait_locked_killable(folio);
		if (!folio_test_uptodate(folio) && !ret)
			ret = xchg(&desc.ctx->error, 0);
	}
out:
	put_nfs_open_context(desc.ctx);
	trace_nfs_aop_readpage_done(inode, folio, ret);
	return ret;
out_unlock:
	folio_unlock(folio);
	trace_nfs_aop_readpage_done(inode, folio, ret);
	return ret;
}

void nfs_readahead(struct readahead_control *ractl)
{
	unsigned int nr_pages = readahead_count(ractl);
	struct file *file = ractl->file;
	struct nfs_readdesc desc;
	struct inode *inode = ractl->mapping->host;
	struct folio *folio;
	int ret;

	trace_nfs_aop_readahead(inode, readahead_pos(ractl), nr_pages);
	nfs_inc_stats(inode, NFSIOS_VFSREADPAGES);
	task_io_account_read(readahead_length(ractl));

	ret = -ESTALE;
	if (NFS_STALE(inode))
		goto out;

	if (file == NULL) {
		ret = -EBADF;
		desc.ctx = nfs_find_open_context(inode, NULL, FMODE_READ);
		if (desc.ctx == NULL)
			goto out;
	} else
		desc.ctx = get_nfs_open_context(nfs_file_open_context(file));

	nfs_pageio_init_read(&desc.pgio, inode, false,
			     &nfs_async_read_completion_ops);

	while ((folio = readahead_folio(ractl)) != NULL) {
		ret = readpage_async_filler(&desc, folio);
		if (ret)
			break;
	}

	nfs_pageio_complete_read(&desc.pgio);

	put_nfs_open_context(desc.ctx);
out:
	trace_nfs_aop_readahead_done(inode, nr_pages, ret);
}

int __init nfs_init_readpagecache(void)
{
	nfs_rdata_cachep = kmem_cache_create("nfs_read_data",
					     sizeof(struct nfs_pgio_header),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL);
	if (nfs_rdata_cachep == NULL)
		return -ENOMEM;

	cxl_mem_init();
	cxl_mem_test();
	cxl_mem_test();
	cxl_mem_test();

	cxl_mem_read1();
	cxl_mem_read2();

	pr_info("The cache initialization is done.");
	return 0;
}

void nfs_destroy_readpagecache(void)
{
	kmem_cache_destroy(nfs_rdata_cachep);
}

static const struct nfs_rw_ops nfs_rw_read_ops = {
	.rw_alloc_header	= nfs_readhdr_alloc,
	.rw_free_header		= nfs_readhdr_free,
	.rw_done		= nfs_readpage_done,
	.rw_result		= nfs_readpage_result,
	.rw_initiate		= nfs_initiate_read,
};

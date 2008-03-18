#include "tc_set.h"
#include "link_set.h"
#include "lq_route.h"
#include "lq_packet.h"
#include "packet.h"
#include "olsr.h"
#include "lq_plugin_default.h"

olsr_linkcost default_calc_cost(const void *ptr) {
  const struct default_lq *lq = ptr;
  
  float etx = (lq->lq < 0.1 || lq->nlq < 0.1 ? LINK_COST_BROKEN : 1.0/(lq->lq * lq->nlq));
  olsr_linkcost cost = (olsr_linkcost)(etx  * LQ_PLUGIN_LC_MULTIPLIER);
  
  if (cost > LINK_COST_BROKEN)
    return LINK_COST_BROKEN;
  if (cost == 0)
    return 1;
  return cost;
}

int default_olsr_serialize_hello_lq_pair(unsigned char *buff, void *ptr) {
  struct default_lq *lq = ptr;
  
  buff[0] = (unsigned char)(lq->lq * 255);
  buff[1] = (unsigned char)(lq->nlq * 255);
  buff[2] = (unsigned char)(0);
  buff[3] = (unsigned char)(0);
  
  return 4;
}

void default_olsr_deserialize_hello_lq_pair(const olsr_u8_t **curr, void *ptr) {
  struct default_lq *lq = ptr;
  
  pkt_get_lq(curr, &lq->lq);
  pkt_get_lq(curr, &lq->nlq);
  pkt_ignore_u16(curr);
}

olsr_bool default_olsr_is_relevant_costchange(olsr_linkcost c1, olsr_linkcost c2) {
  if (c1 > c2) {
    return c2 - c1 > LQ_PLUGIN_RELEVANT_COSTCHANGE;
  }
  return c1 - c2 > LQ_PLUGIN_RELEVANT_COSTCHANGE;
}

int default_olsr_serialize_tc_lq_pair(unsigned char *buff, void *ptr) {
  struct default_lq *lq = ptr;
  
  buff[0] = (unsigned char)(lq->lq * 255);
  buff[1] = (unsigned char)(lq->nlq * 255);
  buff[2] = (unsigned char)(0);
  buff[3] = (unsigned char)(0);
  
  return 4;
}

void default_olsr_deserialize_tc_lq_pair(const olsr_u8_t **curr, void *ptr) {
  struct default_lq *lq = ptr;
  
  pkt_get_lq(curr, &lq->lq);
  pkt_get_lq(curr, &lq->nlq);
  pkt_ignore_u16(curr);
}

olsr_linkcost default_packet_loss_worker(void *ptr, olsr_bool lost) {
  struct default_lq *tlq = ptr;
  float alpha;
  
  // calculate exponental factor for the new link quality, could be directly done in configuration !
  alpha = 1 / (float)(olsr_cnf->lq_wsize);
  
  // exponential moving average
  tlq->lq *= (1 - alpha);
  if (lost == 0) {
    tlq->lq += alpha;
  }
  return default_calc_cost(ptr);
}

void default_olsr_memorize_foreign_hello_lq(void *ptrLocal, void *ptrForeign) {
  struct default_lq *local = ptrLocal;
  struct default_lq *foreign = ptrForeign;
  
  if (foreign) {
    local->nlq = foreign->lq;
  }
  else {
    local->nlq = 0;
  }
}

void default_olsr_copy_link_lq_into_tc(void *target, void *source) {
  memcpy(target, source, sizeof(struct default_lq));
}

void default_olsr_clear_lq(void *target) {
  memset(target, 0, sizeof(struct default_lq));
}

char *default_olsr_print_lq(void *ptr) {
  static char output_buffer[16];
  struct default_lq *lq = ptr;
  
  sprintf(output_buffer, "%2.3f/%2.3f", lq->lq, lq->nlq);
  return output_buffer;
}

char *default_olsr_print_cost(olsr_linkcost cost) {
  static char output_buffer[16];
  sprintf(output_buffer, "%2.3f", ((float)cost)/LQ_PLUGIN_LC_MULTIPLIER);
  return output_buffer;
}

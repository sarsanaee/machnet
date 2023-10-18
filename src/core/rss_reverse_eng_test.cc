/**
 * @file rss_reverse_eng_test.cc
 *
 * Unit tests for the MachnetEngine class.
 */

#include <channel.h>
#include <dpdk.h>
#include <gtest/gtest.h>
#include <machnet_engine.h>
#include <packet.h>
#include <pmd.h>

#include <memory>
#include <numeric>

constexpr const char *file_name(const char *path) {
  const char *file = path;
  while (*path) {
    if (*path++ == '/') {
      file = path;
    }
  }
  return file;
}

const char *fname = file_name(__FILE__);

TEST(BasicMachnetEngineSharedStateTest, SrcPortAlloc) {
  using EthAddr = juggler::net::Ethernet::Address;
  using Ipv4Addr = juggler::net::Ipv4::Address;
  using UdpPort = juggler::net::Udp::Port;
  using MachnetEngineSharedState = juggler::MachnetEngineSharedState;

  EthAddr test_mac{"00:00:00:00:00:01"};
  Ipv4Addr test_ip;
  test_ip.FromString("10.0.0.1");

  MachnetEngineSharedState state({}, {test_mac}, {test_ip});
  std::vector<UdpPort> allocated_ports;
  do {
    auto port = state.SrcPortAlloc(test_ip, [](uint16_t port) { return true; });
    if (!port.has_value()) break;
    allocated_ports.emplace_back(port.value());
  } while (true);

  std::vector<UdpPort> expected_ports;
  expected_ports.resize(MachnetEngineSharedState::kSrcPortMax -
                        MachnetEngineSharedState::kSrcPortMin + 1);
  std::iota(expected_ports.begin(), expected_ports.end(),
            MachnetEngineSharedState::kSrcPortMin);

  EXPECT_EQ(allocated_ports, expected_ports);

  auto release_allocated_ports = [&state,
                                  &test_ip](std::vector<UdpPort> &ports) {
    while (!ports.empty()) {
      state.SrcPortRelease(test_ip, ports.back());
      ports.pop_back();
    }
  };
  release_allocated_ports(allocated_ports);

  // Test whether the lambda condition for port allocation works.
  // Try to allocate all ports divisible by 3.
  auto is_divisible_by_3 = [](uint16_t port) { return port % 3 == 0; };
  do {
    auto port = state.SrcPortAlloc(test_ip, is_divisible_by_3);
    if (!port.has_value()) break;
    allocated_ports.emplace_back(port.value());
  } while (true);

  expected_ports.clear();
  for (size_t p = MachnetEngineSharedState::kSrcPortMin;
       p <= MachnetEngineSharedState::kSrcPortMax; p++) {
    if (is_divisible_by_3(p)) {
      expected_ports.emplace_back(p);
    }
  }

  EXPECT_EQ(allocated_ports, expected_ports);
  release_allocated_ports(allocated_ports);

  auto illegal_condition = [](uint16_t port) { return port == 0; };
  auto port = state.SrcPortAlloc(test_ip, illegal_condition);
  EXPECT_FALSE(port.has_value());
}

TEST(BasicMachnetEngineRSSTest, BasicMachnetEngineRSSTest) {
  using PmdPort = juggler::dpdk::PmdPort;
  using MachnetEngine = juggler::MachnetEngine;
  using UdpPort = juggler::net::Udp::Port;


  const uint32_t kChannelRingSize = 1024;
  juggler::shm::ChannelManager channel_mgr;
  channel_mgr.AddChannel(fname, kChannelRingSize, kChannelRingSize,
                         kChannelRingSize, kChannelRingSize);
  auto channel = channel_mgr.GetChannel(fname);

  juggler::net::Ethernet::Address test_mac("60:45:bd:0e:d6:0b");
  juggler::net::Ipv4::Address src_addr;
  juggler::net::Ipv4::Address dst_addr;
  UdpPort dst_port(1234);
  src_addr.FromString("10.0.0.1");
  dst_addr.FromString("10.0.0.2");
  std::vector<uint8_t> rss_key = {
      0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2,
      0x83, 0x19, 0xdb, 0x1a, 0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9,
      0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7, 0xd9, 0x56,
      0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a};

  std::vector<juggler::net::Ipv4::Address> test_ips = {src_addr};
  auto shared_state = std::make_shared<juggler::MachnetEngineSharedState>(
      rss_key, test_mac, test_ips);

  juggler::MachnetEngineSharedState state({rss_key}, {test_mac}, {test_ips});

  const uint32_t kRingDescNr = 1024;
  auto pmd_port = std::make_shared<PmdPort>(0, 1, 1, kRingDescNr, kRingDescNr);
  pmd_port->InitDriver();
  MachnetEngine engine(pmd_port, 0, 0, shared_state, {channel});

  std::vector<rte_eth_rss_reta_entry64> reta_table;

  LOG(INFO) << "HERE 2";
  reta_table.resize(256 / RTE_ETH_RETA_GROUP_SIZE,
                          {-1ull, {0}});

  pmd_port->CreateRetaTable(reta_table, 5);

  auto rss_lambda = [src_addr, dst_addr, dst_port,
                        // rss_key = rss_key,
                        rss_key = pmd_port->GetRSSKey(),
                        pmd_port = pmd_port,
                        rx_queue_id = 3,
                        reta_table = reta_table](
                        uint16_t port) -> bool {
    rte_thash_tuple ipv4_l3_l4_tuple;
    ipv4_l3_l4_tuple.v4.src_addr = src_addr.address.value();
    ipv4_l3_l4_tuple.v4.dst_addr = dst_addr.address.value();
    ipv4_l3_l4_tuple.v4.sport = port;
    ipv4_l3_l4_tuple.v4.dport = dst_port.port.value();

    rte_thash_tuple reversed_ipv4_l3_l4_tuple;
    reversed_ipv4_l3_l4_tuple.v4.src_addr = dst_addr.address.value();
    reversed_ipv4_l3_l4_tuple.v4.dst_addr = src_addr.address.value();
    reversed_ipv4_l3_l4_tuple.v4.sport = dst_port.port.value();
    reversed_ipv4_l3_l4_tuple.v4.dport = port;

    auto rss_hash =
        rte_softrss(reinterpret_cast<uint32_t *>(&ipv4_l3_l4_tuple),
                    RTE_THASH_V4_L4_LEN, rss_key.data());
    auto reversed_rss_hash = rte_softrss(
        reinterpret_cast<uint32_t *>(&reversed_ipv4_l3_l4_tuple),
        RTE_THASH_V4_L4_LEN, rss_key.data());

    if (pmd_port->GetRSSRXQueueWithRetaTable(reversed_rss_hash, reta_table) != rx_queue_id) {
        // LOG(WARNING) << "Reverse RSS queue does not match "
        //             << pmd_port->GetRSSRXQueueWithRetaTable(reversed_rss_hash,reta_table)
        //             << " vs " << rx_queue_id;
            LOG(INFO) << "HERE";

        return false;
    }


    if (pmd_port->GetRSSRXQueueWithRetaTable(__builtin_bswap32(reversed_rss_hash), reta_table) !=
        rx_queue_id) {
        // LOG(WARNING) << "RSS queue does not match"
        //             << __builtin_bswap32(reversed_rss_hash) << " vs "
        //             << rx_queue_id;
        return false;
    }

    LOG(INFO) << "RSS hash for " << src_addr.ToString() << ":" << port
                << " -> " << dst_addr.ToString() << ":"
                << dst_port.port.value() << " is " << rss_hash
                << " and reversed " << reversed_rss_hash
                << " (queue: " << rx_queue_id << ")";

    return true;
  };


  auto rss_lambda_default = [src_addr, dst_addr, dst_port,
                        // rss_key = rss_key,
                        rss_key = pmd_port->GetRSSKey(),
                        pmd_port = pmd_port,
                        rx_queue_id = 3](
                        uint16_t port) -> bool {
    rte_thash_tuple ipv4_l3_l4_tuple;
    ipv4_l3_l4_tuple.v4.src_addr = src_addr.address.value();
    ipv4_l3_l4_tuple.v4.dst_addr = dst_addr.address.value();
    ipv4_l3_l4_tuple.v4.sport = port;
    ipv4_l3_l4_tuple.v4.dport = dst_port.port.value();

    rte_thash_tuple reversed_ipv4_l3_l4_tuple;
    reversed_ipv4_l3_l4_tuple.v4.src_addr = dst_addr.address.value();
    reversed_ipv4_l3_l4_tuple.v4.dst_addr = src_addr.address.value();
    reversed_ipv4_l3_l4_tuple.v4.sport = dst_port.port.value();
    reversed_ipv4_l3_l4_tuple.v4.dport = port;

    auto rss_hash =
        rte_softrss(reinterpret_cast<uint32_t *>(&ipv4_l3_l4_tuple),
                    RTE_THASH_V4_L4_LEN, rss_key.data());
    auto reversed_rss_hash = rte_softrss(
        reinterpret_cast<uint32_t *>(&reversed_ipv4_l3_l4_tuple),
        RTE_THASH_V4_L4_LEN, rss_key.data());

    if (pmd_port->GetRSSRxQueue(reversed_rss_hash) != rx_queue_id) {
        // LOG(WARNING) << "Reverse RSS queue does not match "
        //             << pmd_port->GetRSSRXQueueWithRetaTable(reversed_rss_hash,reta_table)
        //             << " vs " << rx_queue_id;
        return false;
    }

    if (pmd_port->GetRSSRxQueue(__builtin_bswap32(reversed_rss_hash)) !=
        rx_queue_id) {
        // LOG(WARNING) << "RSS queue does not match"
        //             << __builtin_bswap32(reversed_rss_hash) << " vs "
        //             << rx_queue_id;
        return false;
    }

    LOG(INFO) << "RSS hash for " << src_addr.ToString() << ":" << port
                << " -> " << dst_addr.ToString() << ":"
                << dst_port.port.value() << " is " << rss_hash
                << " and reversed " << reversed_rss_hash
                << " (queue: " << rx_queue_id << ")";

    return true;
  };

  auto port = state.SrcPortAlloc(src_addr, rss_lambda);

  EXPECT_TRUE(port.has_value());
}

// TEST(BasicMachnetEngineTest, BasicMachnetEngineTest) {
//   using PmdPort = juggler::dpdk::PmdPort;
//   using MachnetEngine = juggler::MachnetEngine;

//   const uint32_t kChannelRingSize = 1024;
//   juggler::shm::ChannelManager channel_mgr;
//   channel_mgr.AddChannel(fname, kChannelRingSize, kChannelRingSize,
//                          kChannelRingSize, kChannelRingSize);
//   auto channel = channel_mgr.GetChannel(fname);

//   juggler::net::Ethernet::Address test_mac("60:45:bd:0e:d6:0b");
//   juggler::net::Ipv4::Address test_ip;
//   test_ip.FromString("10.0.0.1");
//   std::vector<uint8_t> rss_key = {};
//   std::vector<juggler::net::Ipv4::Address> test_ips = {test_ip};
//   auto shared_state = std::make_shared<juggler::MachnetEngineSharedState>(
//       rss_key, test_mac, test_ips);
//   const uint32_t kRingDescNr = 1024;
//   auto pmd_port = std::make_shared<PmdPort>(0, 1, 1, kRingDescNr, kRingDescNr);
//   pmd_port->InitDriver();
//   MachnetEngine engine(pmd_port, 0, 0, shared_state, {channel});
//   EXPECT_EQ(engine.GetChannelCount(), 1);
// }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);

  auto kEalOpts = juggler::utils::CmdLineOpts(
      {"-c", "0x0", "-n", "6", "--proc-type=auto", "-a", "63a9:00:02.0" ,"-m", "1024", "--log-level",
       "8"});

  auto d = juggler::dpdk::Dpdk();
  d.InitDpdk(kEalOpts);
  int ret = RUN_ALL_TESTS();
  return ret;
}

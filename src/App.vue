<script setup lang="ts">
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { ConnectivityResult, DnsResult, CertificateInfo } from "./types";

const domain = ref("");
const loading = ref(false);
const result = ref<{
  connectivity: ConnectivityResult;
  dns: DnsResult;
  cert: CertificateInfo;
} | null>(null);

const checkDomain = async () => {
  if (!domain.value) return;
  loading.value = true;
  result.value = null;

  try {
    const [connectivityError, connectivity] = await wrap(
      invoke<ConnectivityResult>("check_connectivity", {
        domain: domain.value,
      })
    );
    const [dnsError, dns] = await wrap(
      invoke<DnsResult>("check_dns", { domain: domain.value })
    );
    const [certError, cert] = await wrap(
      invoke<CertificateInfo>("get_certificate_info", {
        domain: domain.value,
      })
    );

    result.value = {
      connectivity: connectivity ?? { error: "connectivity error" },
      dns: dns ?? { error: "dns error" },
      cert: cert ?? { error: "cert error" },
    };
  } catch (error) {
    console.error(error);
    alert(`错误: ${error}`);
  } finally {
    loading.value = false;
  }
};

function wrap(p: Promise<any>) {
  return p
    .then((res) => {
      return [null, res];
    })
    .catch((error) => {
      return [error, null];
    });
}
</script>

<template>
  <div class="container mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">网络检查工具</h1>

    <!-- 输入区域 -->
    <div class="mb-6">
      <div class="flex gap-2">
        <input
          v-model="domain"
          type="text"
          placeholder="请输入域名（例如：example.com）"
          class="flex-1 px-4 py-2 border rounded"
          :disabled="loading"
        />
        <button
          @click="checkDomain"
          :disabled="!domain || loading"
          class="px-6 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-gray-400"
        >
          {{ loading ? "检查中..." : "开始检查" }}
        </button>
      </div>
    </div>

    <!-- 结果展示区域 -->
    <div v-if="result" class="space-y-6">
      <!-- 连通性检查结果 -->
      <div class="bg-white p-4 rounded shadow">
        <h2 class="text-xl font-semibold mb-4">连通性检查</h2>
        <div class="space-y-2">
          <div class="flex items-center gap-2">
            <span
              :class="{
                'bg-green-100 text-green-800': result.connectivity.is_reachable,
                'bg-red-100 text-red-800': !result.connectivity.is_reachable,
              }"
              class="px-2 py-1 rounded text-sm"
            >
              {{ result.connectivity.is_reachable ? "可访问" : "不可访问" }}
            </span>
            <span class="text-gray-600">
              响应时间: {{ result.connectivity.response_time_ms }}ms
            </span>
          </div>
          <div v-if="result.connectivity.status_code" class="text-gray-600">
            状态码: {{ result.connectivity.status_code }}
          </div>
          <div v-if="result.connectivity.error" class="text-red-600">
            错误: {{ result.connectivity.error }}
          </div>
        </div>
      </div>

      <!-- DNS 记录 -->
      <div class="bg-white p-4 rounded shadow">
        <h2 class="text-xl font-semibold mb-4">DNS 记录</h2>
        <div class="space-y-4">
          <!-- A 记录 -->
          <div v-if="result.dns.a_records.length">
            <h3 class="font-medium text-gray-700 mb-2">A 记录</h3>
            <div class="space-y-1">
              <div
                v-for="record in result.dns.a_records"
                :key="record"
                class="text-gray-600"
              >
                {{ record }}
              </div>
            </div>
          </div>

          <!-- AAAA 记录 -->
          <div v-if="result.dns.aaaa_records.length">
            <h3 class="font-medium text-gray-700 mb-2">AAAA 记录</h3>
            <div class="space-y-1">
              <div
                v-for="record in result.dns.aaaa_records"
                :key="record"
                class="text-gray-600"
              >
                {{ record }}
              </div>
            </div>
          </div>

          <!-- NS 记录 -->
          <div v-if="result.dns.ns_records.length">
            <h3 class="font-medium text-gray-700 mb-2">NS 记录</h3>
            <div class="space-y-1">
              <div
                v-for="record in result.dns.ns_records"
                :key="record"
                class="text-gray-600"
              >
                {{ record }}
              </div>
            </div>
          </div>

          <!-- MX 记录 -->
          <div v-if="result.dns.mx_records.length">
            <h3 class="font-medium text-gray-700 mb-2">MX 记录</h3>
            <div class="space-y-1">
              <div
                v-for="record in result.dns.mx_records"
                :key="record"
                class="text-gray-600"
              >
                {{ record }}
              </div>
            </div>
          </div>

          <!-- TXT 记录 -->
          <div v-if="result.dns.txt_records.length">
            <h3 class="font-medium text-gray-700 mb-2">TXT 记录</h3>
            <div class="space-y-1">
              <div
                v-for="record in result.dns.txt_records"
                :key="record"
                class="text-gray-600"
              >
                {{ record }}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 证书信息 -->
      <div class="bg-white p-4 rounded shadow">
        <h2 class="text-xl font-semibold mb-4">SSL 证书信息</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <div class="text-sm text-gray-500">主题</div>
            <div class="text-gray-700">{{ result.cert.subject }}</div>
          </div>
          <div>
            <div class="text-sm text-gray-500">颁发者</div>
            <div class="text-gray-700">{{ result.cert.issuer }}</div>
          </div>
          <div>
            <div class="text-sm text-gray-500">有效期从</div>
            <div class="text-gray-700">
              {{ new Date(result.cert.valid_from * 1000).toLocaleString() }}
            </div>
          </div>
          <div>
            <div class="text-sm text-gray-500">有效期至</div>
            <div class="text-gray-700">
              {{ new Date(result.cert.valid_until * 1000).toLocaleString() }}
            </div>
          </div>
          <div>
            <div class="text-sm text-gray-500">序列号</div>
            <div class="text-gray-700">{{ result.cert.serial_number }}</div>
          </div>
          <div>
            <div class="text-sm text-gray-500">版本</div>
            <div class="text-gray-700">V{{ result.cert.version }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style>
@tailwind base;
@tailwind components;
@tailwind utilities;
</style>

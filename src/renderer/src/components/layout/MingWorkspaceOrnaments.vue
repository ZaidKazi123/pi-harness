<script setup lang="ts">
import { computed } from 'vue'
import { marketFileUrl } from '@shared/market/urls'
import { themePackForStyle } from '@shared/market/style-packs'
import { useSettingsStore } from '@renderer/stores/settings'

const settings = useSettingsStore()
const pack = computed(() => themePackForStyle(settings.settings?.mascotStyle) ?? 'ming-snow')
const calligraphyScrollUrl = computed(() =>
  marketFileUrl('theme', pack.value, 'assets/calligraphy-scroll.png')
)
const statusScrollUrl = computed(() => marketFileUrl('theme', pack.value, 'assets/status-scroll.png'))
const governanceCalligraphyScrollUrl = marketFileUrl(
  'theme',
  'zhang-juzheng',
  'assets/calligraphy-scroll-governance.png'
)
const ministerCalligraphyScrollUrl = marketFileUrl(
  'theme',
  'zhang-juzheng',
  'assets/calligraphy-scroll-minister.png'
)
const springCalligraphyScrollUrl = marketFileUrl(
  'theme',
  'zhang-juzheng',
  'assets/calligraphy-scroll-spring.png'
)
const snowPlumLanternUrl = marketFileUrl('theme', 'zhang-juzheng', 'assets/snow-plum-lantern.png')
const wangweiStatusScrollUrl = marketFileUrl(
  'theme',
  'zhang-juzheng',
  'assets/status-scroll-wangwei.png'
)

withDefaults(defineProps<{ zhangJuzheng?: boolean }>(), { zhangJuzheng: false })
</script>

<template>
  <div class="ming-workspace-ornaments" data-testid="ming-workspace-ornaments" aria-hidden="true">
    <template v-if="zhangJuzheng">
      <img
        :src="snowPlumLanternUrl"
        alt=""
        class="zhang-snow-ornament zhang-snow-ornament--left"
        data-testid="zhang-snow-ornament-left"
        draggable="false"
      />
      <img
        :src="snowPlumLanternUrl"
        alt=""
        class="zhang-snow-ornament zhang-snow-ornament--right"
        data-testid="zhang-snow-ornament-right"
        draggable="false"
      />
    </template>
    <img
      v-if="!zhangJuzheng"
      :src="calligraphyScrollUrl"
      alt=""
      class="ming-workspace-calligraphy"
      data-testid="ming-workspace-calligraphy"
      draggable="false"
    />
    <div
      v-else
      class="ming-workspace-calligraphy zhang-calligraphy-scroll"
      data-testid="ming-workspace-calligraphy"
    >
      <img
        :src="springCalligraphyScrollUrl"
        alt=""
        data-testid="zhang-calligraphy-scroll-image"
        draggable="false"
      />
    </div>
    <div class="ming-sidebar-scroll" data-testid="ming-sidebar-scroll">
      <img
        :src="zhangJuzheng ? wangweiStatusScrollUrl : statusScrollUrl"
        alt=""
        :data-testid="zhangJuzheng ? 'zhang-wangwei-scroll-image' : undefined"
        draggable="false"
      />
      <div v-if="!zhangJuzheng" class="ming-sidebar-scroll__copy">
        <strong>Great Ming · Star Chart</strong>
        <span>Rivers and mountains in the scroll · Code becomes prose</span>
        <span>A breeze for thought · A lamp through the long night</span>
      </div>
      <span v-if="!zhangJuzheng" class="ming-sidebar-scroll__footer"> A thousand miles of land, wisdom in hand </span>
    </div>
    <div v-if="zhangJuzheng" class="zhang-juzheng-maxim" data-testid="zhang-juzheng-maxim">
      <strong>A day will come to ride the wind and break the waves</strong>
      <span>Hoist the cloud-high sail across the vast sea</span>
      <small>For the good of all</small>
    </div>
    <div v-if="zhangJuzheng" class="zhang-juzheng-vow" data-testid="zhang-juzheng-vow">
      <span>The noble way</span>
      <span>lies in perseverance</span>
      <span>not in hardship</span>
    </div>
    <template v-if="zhangJuzheng">
      <div class="zhang-edge-scroll zhang-edge-scroll--top" data-testid="zhang-edge-scroll-top">
        <img
          :src="governanceCalligraphyScrollUrl"
          alt=""
          data-testid="zhang-edge-scroll-top-image"
          draggable="false"
        />
      </div>
      <div
        class="zhang-edge-scroll zhang-edge-scroll--bottom"
        data-testid="zhang-edge-scroll-bottom"
      >
        <img
          :src="ministerCalligraphyScrollUrl"
          alt=""
          data-testid="zhang-edge-scroll-bottom-image"
          draggable="false"
        />
      </div>
    </template>
  </div>
</template>

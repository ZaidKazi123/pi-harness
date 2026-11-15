import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import MessageView from './MessageView.vue'
import { i18n } from '@renderer/i18n'
import type {
  AgentMessage,
  AssistantMessage,
  ToolResultMessage,
  UserMessage
} from '@shared/types/workspace'

describe('MessageView', () => {
  it('renders images from Pi-native persisted user messages', () => {
    const message: UserMessage = {
      role: 'user',
      content: [
        { type: 'text', text: 'Take a look at this image' },
        { type: 'image', data: 'TQ==', mimeType: 'image/png' }
      ]
    }

    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: { BranchNavigator: true, Dialog: true }
      }
    })

    expect(wrapper.get('.user-message-body p').text()).toBe('Take a look at this image')
    expect(wrapper.get('[data-message-role="user"] .message-role-badge').text()).toBe('Me')
    expect(wrapper.get('.user-message-body img').attributes('src')).toBe(
      'data:image/png;base64,TQ=='
    )
  })

  it('copies user message text from the hover action bar', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    const message: AgentMessage = { role: 'user', content: 'Help me fix this issue' }
    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: { BranchNavigator: true, Dialog: true, ToolCallView: true }
      }
    })
    await wrapper.get('[data-testid="copy-user-message"]').trigger('click')
    expect(writeText).toHaveBeenCalledWith('Help me fix this issue')
  })

  it('copies assistant markdown text without tool blocks from the action bar', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    const message: AssistantMessage = {
      role: 'assistant',
      model: 'test-model',
      provider: 'test',
      content: [
        { type: 'text', text: '**Delivery summary**' },
        { type: 'toolCall', id: 't1', name: 'bash', arguments: {} } as never
      ]
    }
    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: { BranchNavigator: true, Dialog: true, ToolCallView: true, StreamingMarkdown: true }
      }
    })
    await wrapper.get('[data-testid="copy-assistant-message"]').trigger('click')
    expect(writeText).toHaveBeenCalledWith('**Delivery summary**')
  })

  it('uses the configured user display name', () => {
    const message: AgentMessage = { role: 'user', content: 'Please continue' }
    const wrapper = mount(MessageView, {
      props: { message, userName: 'Alex' },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: { BranchNavigator: true, Dialog: true, ToolCallView: true }
      }
    })

    expect(wrapper.get('.message-role-badge').text()).toBe('Alex')
  })

  it('renders expanded Pi skill content as a compact mention', () => {
    const message: AgentMessage = {
      role: 'user',
      content:
        '<skill name="demo-skill" location="/skills/demo-skill/SKILL.md">\n' +
        'References are relative to /skills/demo-skill.\n\n# Long instructions\n</skill>\n\nReview this change'
    }
    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: { BranchNavigator: true, Dialog: true, ToolCallView: true }
      }
    })

    expect(wrapper.get('[data-testid="skill-invocation"]').text()).toBe('@demo-skill')
    expect(wrapper.get('.user-message-body p').text()).toBe('Review this change')
    expect(wrapper.text()).not.toContain('Long instructions')
  })

  it('renders assistant text as safe Markdown', async () => {
    const message: AssistantMessage = {
      role: 'assistant',
      model: 'test-model',
      provider: 'test-provider',
      content: [
        {
          type: 'text',
          text: [
            '## Core capabilities',
            '',
            '**Read code** and analyze it.',
            '',
            '- First item',
            '- Second item',
            '',
            '- [x] Done',
            '',
            '```ts',
            'const answer = 42',
            '```',
            '',
            '<script>alert("unsafe")</script>'
          ].join('\n')
        }
      ]
    }

    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: {
          BranchNavigator: true,
          Dialog: true,
          ToolCallView: true
        }
      }
    })
    await flushPromises()

    expect(wrapper.get('h2').text()).toBe('Core capabilities')
    expect(wrapper.get('strong').text()).toBe('Read code')
    expect(wrapper.get('[data-message-role="assistant"] .message-role-badge').text()).toBe(
      'Assistant'
    )
    expect(wrapper.findAll('li').map((item) => item.text())).toEqual([
      'First item',
      'Second item',
      'Done'
    ])
    expect(wrapper.get('pre code').text()).toBe('const answer = 42')
    expect(wrapper.get('input[type="checkbox"]').attributes()).toMatchObject({
      checked: '',
      disabled: ''
    })
    expect(wrapper.find('script').exists()).toBe(false)
  })

  it('uses the configured assistant display name', async () => {
    const message: AgentMessage = {
      role: 'assistant',
      model: 'test-model',
      provider: 'test-provider',
      content: [{ type: 'text', text: 'Done' }]
    }
    const wrapper = mount(MessageView, {
      props: { message, assistantName: 'Sage' },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: { BranchNavigator: true, Dialog: true, ToolCallView: true }
      }
    })
    await flushPromises()

    expect(wrapper.get('.message-role-badge').text()).toBe('Sage')
  })

  it('collapses tool results by default and exposes output on demand', async () => {
    const message: ToolResultMessage = {
      role: 'toolResult',
      toolCallId: 'tool-1',
      toolName: 'write',
      content: [{ type: 'text', text: '<html>generated output</html>' }]
    }

    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => (key === 'workspace.roleTool' ? 'Tool' : key) },
        stubs: {
          BranchNavigator: true,
          Dialog: true
        }
      }
    })

    const details = wrapper.get('[data-testid="tool-result-details"]')
    expect(details.attributes('open')).toBeUndefined()
    expect(details.get('summary').text()).toContain('Wrote files')
    expect(details.find('pre').exists()).toBe(false)

    ;(details.element as HTMLDetailsElement).open = true
    await details.trigger('toggle')
    expect(details.get('pre').text()).toBe('<html>generated output</html>')
  })

  it('collapses assistant thinking by default and allows expanding it', async () => {
    const message: AssistantMessage = {
      role: 'assistant',
      model: 'test-model',
      provider: 'test-provider',
      content: [{ type: 'thinking', thinking: 'Analyze the problem' }]
    }

    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: {
          BranchNavigator: true,
          Dialog: true,
          ToolCallView: true
        }
      }
    })

    const details = wrapper.get('[data-testid="thinking-details"]')
    expect(details.attributes('open')).toBeUndefined()
    expect(details.text()).toContain('Analyze the problem')

    await details.get('summary').trigger('click')
    expect((details.element as HTMLDetailsElement).open).toBe(true)
  })

  it('shows assistant API errors when the model returns no content', () => {
    const message: AssistantMessage = {
      role: 'assistant',
      model: 'glm-5.3',
      provider: 'volcengine',
      content: [],
      stopReason: 'error',
      errorMessage: '404 status code (no body)'
    }

    const wrapper = mount(MessageView, {
      props: { message },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: {
          BranchNavigator: true,
          Dialog: true,
          ToolCallView: true
        }
      }
    })

    expect(wrapper.get('[data-testid="assistant-error"]').text()).toBe('404 status code (no body)')
  })

  it('does not render empty or whitespace-only messages', () => {
    const messages: AgentMessage[] = [
      { role: 'user', content: '   \n ' },
      {
        role: 'assistant',
        model: 'test-model',
        provider: 'test-provider',
        content: [{ type: 'text', text: '\n  ' }]
      },
      { role: 'custom', customType: '', content: '', display: true }
    ]

    for (const message of messages) {
      const wrapper = mount(MessageView, {
        props: { message },
        global: {
          plugins: [i18n],
          mocks: { $t: (key: string) => key },
          stubs: { BranchNavigator: true, Dialog: true, ToolCallView: true }
        }
      })
      expect(wrapper.find('.message-hud').exists()).toBe(false)
    }
  })

  it('keeps a file-change card visible when the assistant text is empty', () => {
    const message: AssistantMessage = {
      role: 'assistant',
      model: 'test-model',
      provider: 'test-provider',
      content: []
    }
    const wrapper = mount(MessageView, {
      props: {
        message,
        fileChanges: {
          runId: 'run-1',
          status: 'verified',
          files: [],
          additions: 0,
          deletions: 0
        }
      },
      global: {
        plugins: [i18n],
        mocks: { $t: (key: string) => key },
        stubs: {
          BranchNavigator: true,
          Dialog: true,
          ToolCallView: true,
          FileChangesCard: true
        }
      }
    })

    expect(wrapper.find('.message-hud').exists()).toBe(true)
    expect(wrapper.findComponent({ name: 'FileChangesCard' }).exists()).toBe(true)
  })
})

it('collapses native compaction summaries and keeps their raw context out of the initial view', async () => {
  const wrapper = mount(MessageView, {
    props: {
      message: {
        role: 'custom',
        customType: 'compaction',
        display: true,
        content: 'No prior history.\n\n## Original Request\nLong internal context'
      }
    },
    global: { plugins: [i18n], stubs: { BranchNavigator: true, Dialog: true } }
  })
  const details = wrapper.get('[data-testid="compaction-details"]')
  expect(details.attributes('open')).toBeUndefined()
  expect(wrapper.find('.message-role-label').exists()).toBe(false)
  expect(wrapper.text()).not.toContain('Long internal context')
  ;(details.element as HTMLDetailsElement).open = true
  await details.trigger('toggle')
  expect(details.get('pre').text()).toContain('Long internal context')
})

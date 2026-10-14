/**
 * @file tests/unit/test_virtualhid_pen.cpp
 * @brief Normalized pen buttons must not change pressure/contact or tool identity.
 */
#include <gtest/gtest.h>
#include "src/platform/virtualhid_input.h"

TEST(NormalizedPen, BarrelButtonsPreserveActiveStrokeAndHover) {
  platf::virtualhid::input_context_t runtime {lvh::BackendKind::fake};
  platf::virtualhid::client_context_t client {runtime};
  ASSERT_NE(client.pen, nullptr);
  const platf::touch_port_t viewport {0, 0, 3840, 2160, 3840, 2160};
  platf::pen_input_t event {};
  event.toolType = LI_TOOL_TYPE_PEN;
  event.eventType = LI_TOUCH_EVENT_DOWN;
  event.x = 0.3F;
  event.y = 0.6F;
  event.pressureOrDistance = 0.7F;
  platf::virtualhid::pen_update(client, viewport, event);
  auto state = client.pen->last_submitted_tool();
  ASSERT_FLOAT_EQ(state.pressure, 0.7F);
  ASSERT_FLOAT_EQ(state.distance, -1.0F);

  for (const auto buttons : {LI_PEN_BUTTON_PRIMARY, 0, LI_PEN_BUTTON_SECONDARY, 0}) {
    event.eventType = LI_TOUCH_EVENT_BUTTON_ONLY;
    event.penButtons = buttons;
    const auto before = client.pen->submit_count();
    platf::virtualhid::pen_update(client, viewport, event);
    // Exactly a button transition, with no additional place_tool operation.
    EXPECT_EQ(client.pen->submit_count(), before + 1);
    state = client.pen->last_submitted_tool();
    EXPECT_FLOAT_EQ(state.pressure, 0.7F);
    EXPECT_FLOAT_EQ(state.distance, -1.0F);
    EXPECT_FLOAT_EQ(state.x, 0.3F);
    EXPECT_FLOAT_EQ(state.y, 0.6F);
  }
  event.eventType = LI_TOUCH_EVENT_HOVER;
  event.pressureOrDistance = 0.4F;
  platf::virtualhid::pen_update(client, viewport, event);
  event.eventType = LI_TOUCH_EVENT_BUTTON_ONLY;
  event.penButtons = LI_PEN_BUTTON_PRIMARY;
  platf::virtualhid::pen_update(client, viewport, event);
  state = client.pen->last_submitted_tool();
  EXPECT_FLOAT_EQ(state.pressure, -1.0F);
  EXPECT_FLOAT_EQ(state.distance, 0.4F);
}

TEST(NormalizedPen, LeaveAndCancelReleaseButtonsEvenWithStalePeerBits) {
  for (const auto event_type : {LI_TOUCH_EVENT_CANCEL_ALL, LI_TOUCH_EVENT_CANCEL, LI_TOUCH_EVENT_HOVER_LEAVE}) {
    platf::virtualhid::input_context_t runtime {lvh::BackendKind::fake};
    platf::virtualhid::client_context_t client {runtime};
    ASSERT_NE(client.pen, nullptr);
    platf::pen_input_t event {};
    event.eventType = LI_TOUCH_EVENT_DOWN;
    event.toolType = LI_TOOL_TYPE_ERASER;
    event.penButtons = LI_PEN_BUTTON_PRIMARY | LI_PEN_BUTTON_SECONDARY | LI_PEN_BUTTON_TERTIARY;
    event.pressureOrDistance = 0.8F;
    platf::virtualhid::pen_update(client, {}, event);
    ASSERT_EQ(client.pressed_pen_buttons.size(), 3);
    event.eventType = event_type;
    event.toolType = LI_TOOL_TYPE_UNKNOWN;
    platf::virtualhid::pen_update(client, {}, event);
    EXPECT_TRUE(client.pressed_pen_buttons.empty());
    const auto state = client.pen->last_submitted_tool();
    EXPECT_EQ(state.transition, event_type == LI_TOUCH_EVENT_HOVER_LEAVE ? lvh::PointerTransition::leave : lvh::PointerTransition::cancel);
    EXPECT_LT(state.pressure, 0.0F);
  }
}

TEST(NormalizedPen, FailedButtonWriteDoesNotChangeAcceptedState) {
  platf::virtualhid::input_context_t runtime {lvh::BackendKind::fake};
  platf::virtualhid::client_context_t client {runtime};
  ASSERT_NE(client.pen, nullptr);
  platf::pen_input_t event {};
  event.eventType = LI_TOUCH_EVENT_BUTTON_ONLY;
  event.penButtons = LI_PEN_BUTTON_PRIMARY;
  platf::virtualhid::pen_update(client, {}, event);
  ASSERT_TRUE(client.pressed_pen_buttons.contains(lvh::PenButton::primary));
  ASSERT_TRUE(client.pen->close().ok());
  event.penButtons = LI_PEN_BUTTON_SECONDARY;
  platf::virtualhid::pen_update(client, {}, event);
  EXPECT_TRUE(client.pressed_pen_buttons.contains(lvh::PenButton::primary));
  EXPECT_FALSE(client.pressed_pen_buttons.contains(lvh::PenButton::secondary));
  event.eventType = LI_TOUCH_EVENT_CANCEL_ALL;
  platf::virtualhid::pen_update(client, {}, event);
  EXPECT_TRUE(client.pressed_pen_buttons.contains(lvh::PenButton::primary));
}

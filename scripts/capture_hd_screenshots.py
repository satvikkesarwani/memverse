import os
import time
from playwright.sync_api import sync_playwright

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")
os.makedirs(OUTPUT_DIR, exist_ok=True)

URL = "https://memverse-satvikkesarwanis-projects.vercel.app"

def capture_hd_suite():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        # High-res 2x Retina context (2880x1800 physical pixels)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2,
            color_scheme="dark"
        )
        page = context.new_page()
        
        print("Navigating to MEMVERSE...")
        page.goto(URL, wait_until="networkidle")
        page.wait_for_timeout(2000)
        
        # 01. Initial Chat View
        shot1 = os.path.join(OUTPUT_DIR, "01_memverse_main_chat_view.png")
        page.screenshot(path=shot1)
        print("Captured: 01_memverse_main_chat_view.png")
        
        # Send live prompt
        try:
            textarea = page.locator("textarea.composer-input, textarea").first
            if textarea.is_visible():
                textarea.fill("What is my educational background and academic GPA standing?")
                page.keyboard.press("Enter")
                print("Waiting for streaming response...")
                page.wait_for_timeout(5000)
        except Exception as e:
            print("Chat error:", e)
            
        # 02. Completed Chat & Governance Tags
        shot2 = os.path.join(OUTPUT_DIR, "02_chat_response_with_zero_trust_badge.png")
        page.screenshot(path=shot2)
        print("Captured: 02_chat_response_with_zero_trust_badge.png")
        
        # Open Trace Drawer
        try:
            trace_btn = page.locator(".trace-link, button:has-text('Inspect'), button:has-text('Trace')").first
            if trace_btn.is_visible():
                trace_btn.click()
                page.wait_for_timeout(1500)
                
                # 03. 12-Stage Pipeline Trace Radar
                shot3 = os.path.join(OUTPUT_DIR, "03_12_stage_security_trace_radar.png")
                page.screenshot(path=shot3)
                print("Captured: 03_12_stage_security_trace_radar.png")
                
                # 04. Payload & Boundary Tab
                payload_tab = page.locator("button:has-text('Payload'), button:has-text('Boundary')").first
                if payload_tab.is_visible():
                    payload_tab.click()
                    page.wait_for_timeout(1000)
                    shot4 = os.path.join(OUTPUT_DIR, "04_payload_boundary_transformation_diff.png")
                    page.screenshot(path=shot4)
                    print("Captured: 04_payload_boundary_transformation_diff.png")
                
                # Close drawer
                close_btn = page.locator("button.drawer-close, button:has-text('✕')").first
                if close_btn.is_visible():
                    close_btn.click()
                    page.wait_for_timeout(500)
        except Exception as e:
            print("Trace error:", e)
            
        # 05. Memory Registry
        try:
            page.locator("button:has-text('Memory Registry'), button:has-text('Registry')").first.click()
            page.wait_for_timeout(1500)
            shot5 = os.path.join(OUTPUT_DIR, "05_memory_registry_passports.png")
            page.screenshot(path=shot5)
            print("Captured: 05_memory_registry_passports.png")
        except Exception as e:
            print("Registry error:", e)
            
        # 06. Policy Explorer
        try:
            page.locator("button:has-text('Policy Explorer'), button:has-text('Policy')").first.click()
            page.wait_for_timeout(1500)
            shot6 = os.path.join(OUTPUT_DIR, "06_dynamic_policy_matrix.png")
            page.screenshot(path=shot6)
            print("Captured: 06_dynamic_policy_matrix.png")
        except Exception as e:
            print("Policy error:", e)
            
        # 07. Security Lab (Adversarial Testing)
        try:
            page.locator("button:has-text('Security Lab'), button:has-text('Lab')").first.click()
            page.wait_for_timeout(1500)
            shot7 = os.path.join(OUTPUT_DIR, "07_security_lab_adversarial_suite.png")
            page.screenshot(path=shot7)
            print("Captured: 07_security_lab_adversarial_suite.png")
        except Exception as e:
            print("Lab error:", e)
            
        # 08. Event Ledger (Cryptographic Audit)
        try:
            page.locator("button:has-text('Event Ledger'), button:has-text('Ledger')").first.click()
            page.wait_for_timeout(1500)
            shot8 = os.path.join(OUTPUT_DIR, "08_cryptographic_event_ledger.png")
            page.screenshot(path=shot8)
            print("Captured: 08_cryptographic_event_ledger.png")
        except Exception as e:
            print("Ledger error:", e)
            
        # 09. How MEMVERSE Works (Architecture)
        try:
            page.locator("button:has-text('How MEMVERSE Works'), button:has-text('Architecture')").first.click()
            page.wait_for_timeout(1500)
            shot9 = os.path.join(OUTPUT_DIR, "09_how_memverse_works_architecture.png")
            page.screenshot(path=shot9)
            print("Captured: 09_how_memverse_works_architecture.png")
        except Exception as e:
            print("Architecture error:", e)

        browser.close()
        print("All 9 HD screenshots captured and saved to docs/screenshots/")

if __name__ == "__main__":
    capture_hd_suite()

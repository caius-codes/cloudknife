"""
Cloud provider icons for CLI prompts.

Supports Nerd Font icons with automatic fallback to Unicode emoji.
Users can override behavior via environment variables.
"""

import os


def supports_nerd_fonts() -> bool:
    """
    Detect if terminal likely supports Nerd Fonts.

    Uses heuristics based on environment variables:
    - TERM_PROGRAM: Terminal application name
    - Detects popular terminals with good Nerd Font support

    Returns:
        True if Nerd Fonts are likely supported
    """
    term_program = os.environ.get("TERM_PROGRAM", "").lower()

    # Known terminals with excellent Nerd Font support
    nerd_terminals = [
        "iterm",      # iTerm2 (macOS)
        "wezterm",    # WezTerm
        "alacritty",  # Alacritty
        "kitty",      # Kitty
        "hyper",      # Hyper
    ]

    # Check if any known Nerd Font terminal is detected
    for term in nerd_terminals:
        if term in term_program:
            return True

    # Check for VS Code integrated terminal with Nerd Font
    if "vscode" in term_program:
        # VS Code supports Nerd Fonts if editor font is configured
        # Default to emoji for safety
        return False

    # Windows Terminal has good Unicode support
    if os.environ.get("WT_SESSION"):
        return True

    # Default to emoji (safer fallback)
    return False


class CloudIcons:
    """
    Cloud provider icons with automatic Nerd Font detection and fallback.

    Usage:
        icons = CloudIcons()
        print(f"AWS {icons.aws}cloudknife>")

    Environment Variables (Global):
        CLOUDKNIFE_FORCE_EMOJI=1   - Force emoji Unicode (max compatibility)
        CLOUDKNIFE_FORCE_NERD=1    - Force Nerd Font icons
        CLOUDKNIFE_ICONS=emoji     - Use emoji
        CLOUDKNIFE_ICONS=nerd      - Use Nerd Font
        CLOUDKNIFE_ICONS=plain     - No icons (text only)

    Environment Variables (Per-Icon Override):
        CLOUDKNIFE_AWS_ICON=emoji   - Force emoji for AWS only
        CLOUDKNIFE_AWS_ICON=nerd    - Force Nerd Font for AWS only
        CLOUDKNIFE_AWS_ICON=plain   - No icon for AWS
        CLOUDKNIFE_GCP_ICON=emoji   - Force emoji for GCP only
        CLOUDKNIFE_GCP_ICON=nerd    - Force Nerd Font for GCP only
        CLOUDKNIFE_GCP_ICON=plain   - No icon for GCP
        CLOUDKNIFE_AZURE_ICON=emoji - Force emoji for Azure only
        CLOUDKNIFE_AZURE_ICON=nerd  - Force Nerd Font for Azure only
        CLOUDKNIFE_AZURE_ICON=plain - No icon for Azure

    Per-icon overrides take precedence over global settings.
    This allows mixing Nerd Font icons with emoji fallbacks for broken glyphs.
    """

    # Nerd Font icons (Font Awesome / Devicon)
    # These require a Nerd Font to be installed
    NERD_AWS = "\uf0ef"      # nf-dev-aws / nf-fa-aws
    NERD_GCP = "\ue7f1"      # nf-dev-googlecloud
    NERD_AZURE = "\uebd8"    # nf-cod-azure

    # Unicode emoji fallbacks (work everywhere)
    EMOJI_AWS = "⚡"         # Lightning bolt (speed/power)
    EMOJI_GCP = "🔴"        # Red circle (Google colors)
    EMOJI_AZURE = "🔷"      # Blue diamond (Microsoft blue)

    # Generic cloud fallback
    EMOJI_CLOUD = "☁️"

    def __init__(self):
        """Initialize with automatic detection or user override."""
        # Check environment variable overrides
        icons_mode = os.environ.get("CLOUDKNIFE_ICONS", "").lower()

        if icons_mode == "emoji" or os.environ.get("CLOUDKNIFE_FORCE_EMOJI") == "1":
            self.use_nerd_fonts = False
        elif icons_mode == "nerd" or os.environ.get("CLOUDKNIFE_FORCE_NERD") == "1":
            self.use_nerd_fonts = True
        elif icons_mode == "plain":
            self.use_nerd_fonts = None  # No icons
        else:
            # Auto-detect
            self.use_nerd_fonts = supports_nerd_fonts()

        # Per-icon overrides (individual fallback configuration)
        # Allows mixing Nerd Font icons with emoji for broken glyphs
        self.aws_override = os.environ.get("CLOUDKNIFE_AWS_ICON", "").lower()
        self.gcp_override = os.environ.get("CLOUDKNIFE_GCP_ICON", "").lower()
        self.azure_override = os.environ.get("CLOUDKNIFE_AZURE_ICON", "").lower()

    @property
    def aws(self) -> str:
        """AWS icon with space."""
        # Check per-icon override first
        if self.aws_override == "emoji":
            return f"{self.EMOJI_AWS} "
        elif self.aws_override == "nerd":
            return f"{self.NERD_AWS} "
        elif self.aws_override == "plain":
            return ""

        # Fall back to global setting
        if self.use_nerd_fonts is None:
            return ""
        return f"{self.NERD_AWS} " if self.use_nerd_fonts else f"{self.EMOJI_AWS} "

    @property
    def gcp(self) -> str:
        """GCP icon with space."""
        # Check per-icon override first
        if self.gcp_override == "emoji":
            return f"{self.EMOJI_GCP} "
        elif self.gcp_override == "nerd":
            return f"{self.NERD_GCP} "
        elif self.gcp_override == "plain":
            return ""

        # Fall back to global setting
        if self.use_nerd_fonts is None:
            return ""
        return f"{self.NERD_GCP} " if self.use_nerd_fonts else f"{self.EMOJI_GCP} "

    @property
    def azure(self) -> str:
        """Azure icon with space."""
        # Check per-icon override first
        if self.azure_override == "emoji":
            return f"{self.EMOJI_AZURE} "
        elif self.azure_override == "nerd":
            return f"{self.NERD_AZURE} "
        elif self.azure_override == "plain":
            return ""

        # Fall back to global setting
        if self.use_nerd_fonts is None:
            return ""
        return f"{self.NERD_AZURE} " if self.use_nerd_fonts else f"{self.EMOJI_AZURE} "

    @property
    def cloud(self) -> str:
        """Generic cloud icon with space."""
        if self.use_nerd_fonts is None:
            return ""
        return f"{self.EMOJI_CLOUD} "

    def get_icon_info(self) -> dict:
        """
        Get current icon configuration info.

        Returns:
            Dictionary with icon mode and examples
        """
        if self.use_nerd_fonts is None:
            mode = "plain (no icons)"
        elif self.use_nerd_fonts:
            mode = "nerd fonts"
        else:
            mode = "unicode emoji"

        return {
            "mode": mode,
            "auto_detected": os.environ.get("CLOUDKNIFE_ICONS") is None,
            "aws": self.aws.strip() if self.aws else "-",
            "gcp": self.gcp.strip() if self.gcp else "-",
            "azure": self.azure.strip() if self.azure else "-",
            "aws_override": self.aws_override or "none",
            "gcp_override": self.gcp_override or "none",
            "azure_override": self.azure_override or "none",
        }


# Global singleton instance
icons = CloudIcons()


# Convenience function for testing
def test_icons():
    """
    Test icon rendering in current terminal.

    Prints examples of all icon modes for visual verification.
    """
    print("=== CloudKnife Icon Test ===\n")

    # Current configuration
    info = icons.get_icon_info()
    print(f"Current mode: {info['mode']}")
    print(f"Auto-detected: {info['auto_detected']}")
    print()

    # Show current icons
    print("Current icons:")
    print(f"  AWS   {icons.aws}('{info['aws']}') - Override: {info['aws_override']}")
    print(f"  GCP   {icons.gcp}('{info['gcp']}') - Override: {info['gcp_override']}")
    print(f"  Azure {icons.azure}('{info['azure']}') - Override: {info['azure_override']}")
    print()

    # Show all modes
    print("All available modes:")
    print()

    print("1. Nerd Font icons:")
    print(f"   AWS {CloudIcons.NERD_AWS} | GCP {CloudIcons.NERD_GCP} | Azure {CloudIcons.NERD_AZURE}")
    print("   (If you see boxes/?, Nerd Font is not installed)")
    print()

    print("2. Unicode emoji (fallback):")
    print(f"   AWS {CloudIcons.EMOJI_AWS} | GCP {CloudIcons.EMOJI_GCP} | Azure {CloudIcons.EMOJI_AZURE}")
    print("   (Should work on all modern terminals)")
    print()

    print("3. Plain (no icons):")
    print("   AWS | GCP | Azure")
    print()

    # Environment variable hints
    print("Global Configuration:")
    print("  export CLOUDKNIFE_ICONS=emoji  # Force emoji")
    print("  export CLOUDKNIFE_ICONS=nerd   # Force Nerd Font")
    print("  export CLOUDKNIFE_ICONS=plain  # No icons")
    print()

    print("Per-Icon Configuration (mix Nerd Font with emoji fallbacks):")
    print("  # Force AWS to use emoji if Nerd Font glyph is broken")
    print("  export CLOUDKNIFE_AWS_ICON=emoji")
    print()
    print("  # Use Nerd Font for GCP and Azure, emoji for AWS")
    print("  export CLOUDKNIFE_ICONS=nerd")
    print("  export CLOUDKNIFE_AWS_ICON=emoji")
    print()
    print("  # Hide only Azure icon")
    print("  export CLOUDKNIFE_AZURE_ICON=plain")
    print()

    # Terminal detection info
    term_program = os.environ.get("TERM_PROGRAM", "unknown")
    print(f"Terminal: {term_program}")
    print(f"Nerd Font support detected: {supports_nerd_fonts()}")


if __name__ == "__main__":
    # Run test when executed directly
    test_icons()

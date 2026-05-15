# TraceProbe Figure Drop-In Directory

Put final paper figure PDFs in this directory with these exact filenames:

```text
fig1_pipeline.pdf
fig2_taxonomy.pdf
fig3_main_results.pdf
fig4_internal_authority.pdf
fig5_replay_localization.pdf
fig6_compositional.pdf
```

The TeX draft uses `\IfFileExists`, so missing files render as boxed placeholders.
When a file exists here, it is included automatically.

See `configs/mvp/paper/figure_drawing_guide.md` for panel layouts, data sources,
and caption requirements.

